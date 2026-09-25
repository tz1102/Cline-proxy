package app

import (
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
// 模型池：用户指定的重点模型白名单
// 启用后 /v1/* 端点的 model 必须命中池内任一条目（不区分大小写子串匹配，
// 支持 kimi-k3 这类短名自动命中 moonshotai/kimi-k3），否则 400 拒绝。
// 池内模型正常走上游路由，是否免费由上游计费决定。
// 持久化: data/model-pool.json
// ============================================================================

type modelPoolEntry struct {
	ID      string    `json:"id"`      // 匹配串（短名或完整 ID）
	AddedAt time.Time `json:"addedAt"`
	Note    string    `json:"note,omitempty"`
}

type modelPoolData struct {
	Enabled bool             `json:"enabled"`
	Models  []modelPoolEntry `json:"models"`
	// FreeOnly 仅免费放行：池内模型还需在官方免费清单中才放行，
	// 否则拦截（防止误用付费模型烧掉账号赠金）。nil 视为 true（旧行为兼容）。
	FreeOnly *bool `json:"freeOnly,omitempty"`
}

var (
	modelPoolMu sync.RWMutex
	modelPool   *modelPoolData
	modelPoolOn sync.Once
)

const modelPoolFile = "model-pool.json"

func loadModelPool() *modelPoolData {
	modelPoolOn.Do(func() {
		mp := &modelPoolData{}
		raw, err := os.ReadFile(kit.ResolveDataPath(modelPoolFile))
		if err == nil && json.Unmarshal(raw, mp) == nil && mp.Models != nil {
			modelPool = mp
			return
		}
		// 首次运行：预置默认重点模型
		now := time.Now()
		modelPool = &modelPoolData{
			Enabled: true,
			Models: []modelPoolEntry{
				{ID: "deepseek-v4.1-flash", AddedAt: now},
				{ID: "kimi-k3", AddedAt: now},
				{ID: "glm-5.3", AddedAt: now},
			},
		}
		saveModelPoolLocked()
	})
	return modelPool
}

// saveModelPoolLocked 落盘（调用方需持有写锁或处于初始化阶段）
func saveModelPoolLocked() {
	data, err := json.MarshalIndent(modelPool, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(kit.ResolveDataPath(modelPoolFile), data, 0600); err != nil {
		log.Printf("model pool save failed: %v", err)
	}
}

// modelPoolMatches 池条目与模型 ID 的匹配规则：不区分大小写子串
func modelPoolMatches(entry, model string) bool {
	entry = strings.ToLower(strings.TrimSpace(entry))
	model = strings.ToLower(strings.TrimSpace(model))
	return entry != "" && model != "" && strings.Contains(model, entry)
}

// isFreeOnly 池条目是否要求"当前免费"才放行（默认开）
func (mp *modelPoolData) isFreeOnly() bool {
	return mp.FreeOnly == nil || *mp.FreeOnly
}

// modelPoolCheck 判定请求模型：返回 "" 放行；"pool"=不在池内；"paid"=池内但当前不免费
func modelPoolCheck(model string) string {
	mp := loadModelPool()
	modelPoolMu.RLock()
	defer modelPoolMu.RUnlock()
	if !mp.Enabled || len(mp.Models) == 0 {
		return ""
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return "" // 空 model 走默认模型逻辑，不在拦截范围
	}
	hit := false
	for _, e := range mp.Models {
		if modelPoolMatches(e.ID, model) {
			hit = true
			break
		}
	}
	if !hit {
		return "pool"
	}
	if !mp.isFreeOnly() || modelIsFreeNow(model) {
		return ""
	}
	return "paid"
}

// modelIsFreeNow 与官方免费清单做双向子串匹配（短名/带前缀都能命中）
func modelIsFreeNow(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return false
	}
	for id := range freeModelSet() {
		if strings.Contains(id, m) || strings.Contains(m, id) {
			return true
		}
	}
	return false
}

// modelPoolAllows 拦截判定：未启用或池空时放行一切
func modelPoolAllows(model string) bool {
	return modelPoolCheck(model) == ""
}

func modelPoolRejectError(model string) map[string]any {
	mp := loadModelPool()
	modelPoolMu.RLock()
	ids := make([]string, 0, len(mp.Models))
	for _, e := range mp.Models {
		if s := strings.TrimSpace(e.ID); s != "" {
			ids = append(ids, s)
		}
	}
	freeOnly := mp.isFreeOnly()
	modelPoolMu.RUnlock()

	var msg string
	switch modelPoolCheck(model) {
	case "paid":
		msg = fmt.Sprintf("model %q 在模型池内，但当前不在官方免费清单，放行会消耗账号 credits 赠金，已拦截。它回归免费后会自动放行（可在后台关闭\"仅免费放行\"强制使用）", model)
	default:
		msg = fmt.Sprintf("model %q 不在模型池白名单内，当前池子: %v （后台 /admin/ → 设置 → 模型池 可修改）", model, ids)
	}
	if !freeOnly {
		msg += "（当前\"仅免费放行\"已关闭，池内付费模型会消耗赠金）"
	}
	return map[string]any{
		"error": map[string]string{
			"message": msg,
			"type":    "invalid_request_error",
		},
	}
}

// freeModelSet 当前免费清单的 ID 集合（供状态展示）。
// 只统计官方动态同步且仍 active 的模型，内置 seed 条目不代表官方清单。
func freeModelSet() map[string]bool {
	set := map[string]bool{}
	for _, m := range getFreeModels() {
		if m.Seed || m.Status != ModelActive {
			continue
		}
		set[strings.ToLower(m.ID)] = true
	}
	return set
}

// ============ Admin API ============

// GET /admin/api/model-pool
func handleModelPoolGet(w http.ResponseWriter, r *http.Request) {
	mp := loadModelPool()
	modelPoolMu.RLock()
	defer modelPoolMu.RUnlock()

	free := freeModelSet()
	entries := make([]map[string]any, 0, len(mp.Models))
	for _, e := range mp.Models {
		freeNow := false
		for id := range free {
			if modelPoolMatches(e.ID, id) {
				freeNow = true
				break
			}
		}
		entries = append(entries, map[string]any{
			"id":      e.ID,
			"addedAt": e.AddedAt,
			"freeNow": freeNow,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data": map[string]any{
			"enabled":  mp.Enabled,
			"freeOnly": mp.isFreeOnly(),
			"models":   entries,
		},
	})
}

// POST /admin/api/model-pool/add  {"id": "kimi-k3"}
func handleModelPoolAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ID) == "" {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "id is required"})
		return
	}
	mp := loadModelPool()
	modelPoolMu.Lock()
	defer modelPoolMu.Unlock()
	for _, e := range mp.Models {
		if strings.EqualFold(strings.TrimSpace(e.ID), strings.TrimSpace(req.ID)) {
			writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "already in pool"})
			return
		}
	}
	mp.Models = append(mp.Models, modelPoolEntry{ID: strings.TrimSpace(req.ID), AddedAt: time.Now()})
	saveModelPoolLocked()
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "added"})
}

// POST /admin/api/model-pool/remove  {"id": "kimi-k3"}
func handleModelPoolRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ID) == "" {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "id is required"})
		return
	}
	mp := loadModelPool()
	modelPoolMu.Lock()
	defer modelPoolMu.Unlock()
	out := mp.Models[:0]
	removed := 0
	for _, e := range mp.Models {
		if strings.EqualFold(strings.TrimSpace(e.ID), strings.TrimSpace(req.ID)) {
			removed++
			continue
		}
		out = append(out, e)
	}
	mp.Models = out
	if removed > 0 {
		saveModelPoolLocked()
	}
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("removed %d", removed)})
}

// POST /admin/api/model-pool/toggle  {"enabled": true} 或 {"freeOnly": true}
func handleModelPoolToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req struct {
		Enabled  *bool `json:"enabled"`
		FreeOnly *bool `json:"freeOnly"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Enabled == nil && req.FreeOnly == nil) {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "enabled or freeOnly is required"})
		return
	}
	mp := loadModelPool()
	modelPoolMu.Lock()
	defer modelPoolMu.Unlock()
	if req.Enabled != nil {
		mp.Enabled = *req.Enabled
	}
	if req.FreeOnly != nil {
		mp.FreeOnly = req.FreeOnly
	}
	saveModelPoolLocked()
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: fmt.Sprintf("enabled=%v freeOnly=%v", mp.Enabled, mp.isFreeOnly())})
}
