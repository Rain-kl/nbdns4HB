package web

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"

	"github.com/naiba/nbdns/internal/model"
	"github.com/naiba/nbdns/internal/stats"
	"github.com/naiba/nbdns/pkg/logger"
)

//go:embed static/*
var staticFiles embed.FS

// Handler Web服务处理器
type Handler struct {
	stats         stats.StatsRecorder
	version       string
	checkUpdateCh chan<- struct{}
	logger        logger.Logger
	hijackManager *model.HijackManager
}

// NewHandler 创建Web处理器
func NewHandler(s stats.StatsRecorder, ver string, checkCh chan<- struct{}, log logger.Logger, hm *model.HijackManager) *Handler {
	return &Handler{
		stats:         s,
		version:       ver,
		checkUpdateCh: checkCh,
		logger:        log,
		hijackManager: hm,
	}
}

// RegisterRoutes 注册路由
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// API路由
	mux.HandleFunc("/api/stats", h.handleStats)
	mux.HandleFunc("/api/stats/reset", h.handleStatsReset)
	mux.HandleFunc("/api/version", h.handleVersion)
	mux.HandleFunc("/api/check-update", h.handleCheckUpdate)
	// 劫持相关API
	mux.HandleFunc("/api/hijack", h.handleHijack)
	mux.HandleFunc("/api/hijack/list", h.handleHijackList)

	// 静态文件服务
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		h.logger.Printf("Failed to load static files: %v", err)
		return
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
}

// handleStats 处理统计信息请求
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	// 只允许GET请求
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取统计快照
	snapshot := h.stats.GetSnapshot()

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// 编码JSON并返回
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		h.logger.Printf("Error encoding stats JSON: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// ResetResponse 重置响应
type ResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// handleStatsReset 处理统计数据重置请求
func (h *Handler) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	// 只允许POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 重置统计数据
	h.stats.Reset()
	h.logger.Printf("Statistics reset by user request")

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 返回成功响应
	if err := json.NewEncoder(w).Encode(ResetResponse{
		Success: true,
		Message: "统计数据已重置",
	}); err != nil {
		h.logger.Printf("Error encoding reset response JSON: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// VersionResponse 版本信息响应
type VersionResponse struct {
	Version string `json:"version"`
}

// handleVersion 处理版本查询请求
func (h *Handler) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ver := h.version
	if ver == "" {
		ver = "0.0.0"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	if err := json.NewEncoder(w).Encode(VersionResponse{Version: ver}); err != nil {
		h.logger.Printf("Error encoding version JSON: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// UpdateCheckResponse 更新检查响应
type UpdateCheckResponse struct {
	HasUpdate      bool   `json:"has_update"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Message        string `json:"message"`
}

// handleCheckUpdate 处理检查更新请求（生产者2：用户手动触发）
func (h *Handler) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ver := h.version
	if ver == "" {
		ver = "0.0.0"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// 触发后台检查更新（非阻塞）
	select {
	case h.checkUpdateCh <- struct{}{}:
		h.logger.Printf("Update check triggered by user")
		json.NewEncoder(w).Encode(UpdateCheckResponse{
			HasUpdate:      false,
			CurrentVersion: ver,
			LatestVersion:  ver,
			Message:        "已触发更新检查，请查看服务器日志",
		})
	default:
		// 如果通道已满，说明已经在检查中
		json.NewEncoder(w).Encode(UpdateCheckResponse{
			HasUpdate:      false,
			CurrentVersion: ver,
			LatestVersion:  ver,
			Message:        "更新检查正在进行中",
		})
	}
}

// HijackRequest 劫持请求参数
type HijackRequest struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
}

// HijackResponse 劫持响应
type HijackResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// handleHijack 处理劫持规则的增删操作
// POST 添加或更新劫持规则
// DELETE 删除劫持规则
func (h *Handler) handleHijack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if h.hijackManager == nil {
		http.Error(w, `{"success":false,"message":"Hijack manager not initialized"}`, http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodPost:
		// 添加或更新劫持规则
		body, err := io.ReadAll(r.Body)
		if err != nil {
			json.NewEncoder(w).Encode(HijackResponse{
				Success: false,
				Message: "Failed to read request body: " + err.Error(),
			})
			return
		}
		defer r.Body.Close()

		var req HijackRequest
		if err := json.Unmarshal(body, &req); err != nil {
			json.NewEncoder(w).Encode(HijackResponse{
				Success: false,
				Message: "Invalid JSON: " + err.Error(),
			})
			return
		}

		if req.Domain == "" || req.IPv4 == "" {
			json.NewEncoder(w).Encode(HijackResponse{
				Success: false,
				Message: "Domain and IPv4 are required",
			})
			return
		}

		if err := h.hijackManager.AddRule(req.Domain, req.IPv4); err != nil {
			json.NewEncoder(w).Encode(HijackResponse{
				Success: false,
				Message: "Failed to add hijack rule: " + err.Error(),
			})
			return
		}

		h.logger.Printf("Hijack rule added via API: %s -> %s", req.Domain, req.IPv4)
		json.NewEncoder(w).Encode(HijackResponse{
			Success: true,
			Message: "Hijack rule added successfully",
		})

	case http.MethodDelete:
		// 删除劫持规则
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			json.NewEncoder(w).Encode(HijackResponse{
				Success: false,
				Message: "Domain parameter is required",
			})
			return
		}

		if err := h.hijackManager.RemoveRule(domain); err != nil {
			json.NewEncoder(w).Encode(HijackResponse{
				Success: false,
				Message: "Failed to remove hijack rule: " + err.Error(),
			})
			return
		}

		h.logger.Printf("Hijack rule removed via API: %s", domain)
		json.NewEncoder(w).Encode(HijackResponse{
			Success: true,
			Message: "Hijack rule removed successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHijackList 获取所有劫持规则
func (h *Handler) handleHijackList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	if h.hijackManager == nil {
		http.Error(w, `{"success":false,"message":"Hijack manager not initialized"}`, http.StatusInternalServerError)
		return
	}

	rules := h.hijackManager.GetAllRules()
	if err := json.NewEncoder(w).Encode(rules); err != nil {
		h.logger.Printf("Error encoding hijack rules JSON: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
