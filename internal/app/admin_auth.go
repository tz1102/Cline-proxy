package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"cline-go-proxy/internal/kit"
)

// ============================================================================
// Admin 后台认证层：
// - 用户名+密码登录（SHA-256 加盐哈希，不存明文）
// - 首次启动自动生成随机密码并打印到日志；可用环境变量 ADMIN_USER/ADMIN_PASS 覆盖
// - session cookie（HttpOnly + SameSite=Lax），服务重启后失效
// - 防爆破：同 IP 连续 5 次失败锁定 5 分钟
// - 持久化: data/admin-auth.json（在 .gitignore 的 data/ 内，不会入库）
// ============================================================================

const (
	adminAuthFile     = "admin-auth.json"
	adminSessionTTL   = 7 * 24 * time.Hour
	adminMaxFails     = 5
	adminLockDuration = 5 * time.Minute
)

type adminAuthData struct {
	Username     string    `json:"username"`
	Salt         string    `json:"salt"`
	PasswordHash string    `json:"passwordHash"`
	CreatedAt    time.Time `json:"createdAt"`

	scratchPassword string `json:"-"` // 仅初始化时打印一次明文，不落盘
}

var (
	adminAuth   *adminAuthData
	adminAuthMu sync.Mutex

	adminSessions   = make(map[string]time.Time) // token -> 过期时间
	adminSessionsMu sync.Mutex

	adminFails   = make(map[string]*failEntry) // ip -> 失败记录
	adminFailsMu sync.Mutex
)

type failEntry struct {
	count     int
	lockUntil time.Time
}

func hashAdminPassword(salt, password string) string {
	h := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(h[:])
}

func loadAdminAuth() *adminAuthData {
	adminAuthMu.Lock()
	defer adminAuthMu.Unlock()
	if adminAuth != nil {
		return adminAuth
	}
	path := kit.ResolveDataPath(adminAuthFile)
	if raw, err := os.ReadFile(path); err == nil {
		var d adminAuthData
		if json.Unmarshal(raw, &d) == nil && d.Username != "" && d.PasswordHash != "" {
			adminAuth = &d
			return adminAuth
		}
	}
	// 首次初始化
	d := &adminAuthData{CreatedAt: time.Now(), Username: "admin"}
	if envUser, envPass := os.Getenv("ADMIN_USER"), os.Getenv("ADMIN_PASS"); envUser != "" && envPass != "" {
		d.Username = envUser
		d.scratchPassword = envPass
		log.Printf("  admin auth: using ADMIN_USER / ADMIN_PASS from environment")
	} else {
		d.scratchPassword = randomPassword(12)
		log.Printf("==========================================================")
		log.Printf("  admin 后台首次初始化登录凭据：")
		log.Printf("    用户名: %s", d.Username)
		log.Printf("    密码:   %s", d.scratchPassword)
		log.Printf("  （仅此次打印明文，请尽快登录后在设置页修改）")
		log.Printf("==========================================================")
	}
	d.Salt = randHex(16)
	d.PasswordHash = hashAdminPassword(d.Salt, d.scratchPassword)
	d.scratchPassword = ""
	if data, err := json.MarshalIndent(d, "", "  "); err == nil {
		_ = os.WriteFile(path, data, 0600)
	}
	adminAuth = d
	return adminAuth
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randomPassword 生成易读随机密码（剔除 0O1lI 等易混淆字符）
func randomPassword(n int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

// ---- session ----

func validSession(token string) bool {
	if token == "" {
		return false
	}
	adminSessionsMu.Lock()
	defer adminSessionsMu.Unlock()
	exp, ok := adminSessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(adminSessions, token)
		return false
	}
	return true
}

// ---- 防爆破 ----

func loginAllowed(ip string) (bool, time.Duration) {
	adminFailsMu.Lock()
	defer adminFailsMu.Unlock()
	e, ok := adminFails[ip]
	if !ok {
		return true, 0
	}
	if time.Now().Before(e.lockUntil) {
		return false, time.Until(e.lockUntil)
	}
	return true, 0
}

func recordLoginFail(ip string) {
	adminFailsMu.Lock()
	defer adminFailsMu.Unlock()
	e := adminFails[ip]
	if e == nil {
		e = &failEntry{}
		adminFails[ip] = e
	}
	e.count++
	if e.count >= adminMaxFails {
		e.lockUntil = time.Now().Add(adminLockDuration)
		e.count = 0
		log.Printf("  admin auth: %s locked for %v after %d failed attempts", ip, adminLockDuration, adminMaxFails)
	}
}

func recordLoginSuccess(ip string) {
	adminFailsMu.Lock()
	defer adminFailsMu.Unlock()
	delete(adminFails, ip)
}

// clientIP 取直连地址（不信任 X-Forwarded-For，防伪造绕过限速）
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

// ---- handlers & middleware ----

const adminSessionCookie = "cline_admin_sess"

// authMiddleware 登录校验：API 返回 401，页面请求重定向到登录页
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loadAdminAuth()
		if c, err := r.Cookie(adminSessionCookie); err == nil && validSession(c.Value) {
			next(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/api/") {
			writeAPI(w, http.StatusUnauthorized, apiResponse{Error: "unauthorized: 请先登录"})
			return
		}
		http.Redirect(w, r, "/admin/login", http.StatusFound)
	}
}

// adminHandler 同源 admin 专用包装：不设置 ACAO:*（后台为同源应用无需 CORS，
// 同时消除"任意站点可跨域读取后台数据"的隐患），并包一层登录校验。
func adminHandler(h http.HandlerFunc) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	})
}

// adminHandlerOpen 免登录端点（登录）专用：同样不设 ACAO
func adminHandlerOpen(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

// GET /admin/login 登录页
func adminLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if c, err := r.Cookie(adminSessionCookie); err == nil && validSession(c.Value) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(adminLoginHTML))
}

// POST /admin/api/login  {username, password}
func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	ip := clientIP(r)
	if ok, wait := loginAllowed(ip); !ok {
		writeAPI(w, http.StatusTooManyRequests, apiResponse{Error: fmt.Sprintf("尝试次数过多，已被锁定，请 %s 后再试", formatDuration(wait))})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "invalid JSON"})
		return
	}
	cred := loadAdminAuth()
	uOk := subtle.ConstantTimeCompare([]byte(req.Username), []byte(cred.Username)) == 1
	pOk := subtle.ConstantTimeCompare([]byte(hashAdminPassword(cred.Salt, req.Password)), []byte(cred.PasswordHash)) == 1
	if !uOk || !pOk {
		recordLoginFail(ip)
		log.Printf("  admin login failed from %s", ip)
		writeAPI(w, http.StatusUnauthorized, apiResponse{Error: "用户名或密码错误"})
		return
	}
	recordLoginSuccess(ip)
	token := randHex(32)
	adminSessionsMu.Lock()
	now := time.Now()
	for t, exp := range adminSessions {
		if now.After(exp) {
			delete(adminSessions, t)
		}
	}
	adminSessions[token] = now.Add(adminSessionTTL)
	adminSessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(adminSessionTTL.Seconds()),
	})
	log.Printf("  admin login ok from %s", ip)
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "login ok"})
}

// POST /admin/api/logout
func handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	if c, err := r.Cookie(adminSessionCookie); err == nil {
		adminSessionsMu.Lock()
		delete(adminSessions, c.Value)
		adminSessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Value: "", Path: "/admin", HttpOnly: true, MaxAge: -1})
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "logged out"})
}

// POST /admin/api/change-password  {oldPassword, newPassword}
func handleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "invalid JSON"})
		return
	}
	if len(req.NewPassword) < 8 {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "新密码至少 8 位"})
		return
	}
	cred := loadAdminAuth()
	if subtle.ConstantTimeCompare([]byte(hashAdminPassword(cred.Salt, req.OldPassword)), []byte(cred.PasswordHash)) != 1 {
		writeAPI(w, http.StatusUnauthorized, apiResponse{Error: "旧密码错误"})
		return
	}
	adminAuthMu.Lock()
	cred.Salt = randHex(16)
	cred.PasswordHash = hashAdminPassword(cred.Salt, req.NewPassword)
	if data, err := json.MarshalIndent(cred, "", "  "); err == nil {
		_ = os.WriteFile(kit.ResolveDataPath(adminAuthFile), data, 0600)
	}
	adminAuthMu.Unlock()
	// 作废所有旧 session，要求重新登录
	adminSessionsMu.Lock()
	adminSessions = make(map[string]time.Time)
	adminSessionsMu.Unlock()
	log.Printf("  admin password changed (all sessions invalidated)")
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "密码已修改，请重新登录"})
}

const adminLoginHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · Cline 代理后台</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #f3f5f9; color: #1c2333;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #12161f; color: #e8ecf4; }
    .card { background: #1b2130 !important; border-color: #2a3247 !important; }
    input { background: #12161f !important; color: #e8ecf4 !important; border-color: #2a3247 !important; }
  }
  .card {
    width: 340px; padding: 34px 30px; border-radius: 14px;
    background: #ffffff; border: 1px solid #e3e8f0;
    box-shadow: 0 8px 30px rgba(0,0,0,.08);
  }
  h1 { font-size: 19px; text-align: center; margin-bottom: 6px; }
  .sub { font-size: 12.5px; opacity: .6; text-align: center; margin-bottom: 22px; }
  label { display: block; font-size: 12.5px; margin: 12px 0 5px; opacity: .75; }
  input {
    width: 100%; padding: 10px 12px; border-radius: 8px;
    border: 1px solid #d6dce6; font-size: 14px; outline: none;
  }
  input:focus { border-color: #4f7cff; }
  button {
    width: 100%; margin-top: 20px; padding: 11px; border: none; border-radius: 8px;
    background: #4f7cff; color: #fff; font-size: 14.5px; cursor: pointer;
  }
  button:hover { background: #3f6cf0; }
  button:disabled { opacity: .55; cursor: wait; }
  .err { color: #d84b4b; font-size: 12.5px; margin-top: 12px; min-height: 16px; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <h1>⚡ Cline 代理后台</h1>
  <div class="sub">请登录后继续</div>
  <label>用户名</label>
  <input type="text" id="u" autocomplete="username" autofocus>
  <label>密码</label>
  <input type="password" id="p" autocomplete="current-password">
  <button id="btn" onclick="doLogin()">登 录</button>
  <div class="err" id="err"></div>
</div>
<script>
async function doLogin() {
  const err = document.getElementById('err');
  err.textContent = '';
  const btn = document.getElementById('btn');
  btn.disabled = true;
  try {
    const res = await fetch('/admin/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('u').value.trim(),
        password: document.getElementById('p').value
      })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.success) { location.href = '/admin/'; return; }
    err.textContent = data.error || ('登录失败 (' + res.status + ')');
  } catch (e) { err.textContent = '网络错误：' + e.message; }
  btn.disabled = false;
}
document.getElementById('p').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
document.getElementById('u').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('p').focus(); });
</script>
</body>
</html>`
