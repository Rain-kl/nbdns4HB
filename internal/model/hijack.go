package model

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/naiba/nbdns/pkg/logger"
)

// HijackRule 表示一个IP劫持规则
type HijackRule struct {
	Domain string `json:"domain"` // 域名（规范化为小写，不含尾部点）
	IPv4   string `json:"ipv4"`   // 优选IPv4地址
}

// HijackManager 管理DNS劫持规则
type HijackManager struct {
	rules    map[string]string // domain -> ipv4
	mu       sync.RWMutex
	dataPath string
	logger   logger.Logger
}

// NewHijackManager 创建一个新的劫持管理器
func NewHijackManager(dataPath string, log logger.Logger) *HijackManager {
	hm := &HijackManager{
		rules:    make(map[string]string),
		dataPath: dataPath,
		logger:   log,
	}

	// 加载持久化的规则
	if err := hm.Load(); err != nil {
		log.Printf("Failed to load hijack rules: %v (starting with empty rules)", err)
	}

	return hm
}

// normalizeDomain 规范化域名：转小写，去除尾部点
func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// AddRule 添加或更新一个劫持规则
func (hm *HijackManager) AddRule(domain, ipv4 string) error {
	// 验证IP地址格式
	ip := net.ParseIP(ipv4)
	if ip == nil || ip.To4() == nil {
		return &net.ParseError{Type: "IP address", Text: ipv4}
	}

	domain = normalizeDomain(domain)
	if domain == "" {
		return &net.ParseError{Type: "domain", Text: "empty domain"}
	}

	hm.mu.Lock()
	hm.rules[domain] = ipv4
	hm.mu.Unlock()

	hm.logger.Printf("Added hijack rule: %s -> %s", domain, ipv4)

	// 持久化规则
	if err := hm.Save(); err != nil {
		hm.logger.Printf("Failed to save hijack rules: %v", err)
		return err
	}

	return nil
}

// RemoveRule 删除一个劫持规则
func (hm *HijackManager) RemoveRule(domain string) error {
	domain = normalizeDomain(domain)

	hm.mu.Lock()
	delete(hm.rules, domain)
	hm.mu.Unlock()

	hm.logger.Printf("Removed hijack rule: %s", domain)

	// 持久化规则
	if err := hm.Save(); err != nil {
		hm.logger.Printf("Failed to save hijack rules: %v", err)
		return err
	}

	return nil
}

// GetRule 获取指定域名的劫持IP
func (hm *HijackManager) GetRule(domain string) (string, bool) {
	domain = normalizeDomain(domain)

	hm.mu.RLock()
	defer hm.mu.RUnlock()

	ipv4, exists := hm.rules[domain]
	return ipv4, exists
}

// GetAllRules 获取所有劫持规则
func (hm *HijackManager) GetAllRules() []HijackRule {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	rules := make([]HijackRule, 0, len(hm.rules))
	for domain, ipv4 := range hm.rules {
		rules = append(rules, HijackRule{
			Domain: domain,
			IPv4:   ipv4,
		})
	}

	return rules
}

// ApplyHijack 应用劫持规则到DNS响应
// 只修改A记录的IP地址，不影响其他记录（特别是HTTPS/ECH记录）
func (hm *HijackManager) ApplyHijack(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) == 0 {
		return false
	}

	// 提取查询的域名
	queryDomain := normalizeDomain(msg.Question[0].Name)

	// 检查是否有劫持规则
	hijackIP, exists := hm.GetRule(queryDomain)
	if !exists {
		return false
	}

	// 检查是否有A记录需要劫持
	hasARecord := false
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			hasARecord = true
			break
		}
	}

	if !hasARecord {
		return false
	}

	// 只替换A记录的IP地址，保留其他所有记录
	modified := false
	for i, answer := range msg.Answer {
		if aRecord, ok := answer.(*dns.A); ok {
			oldIP := aRecord.A.String()
			aRecord.A = net.ParseIP(hijackIP).To4()
			msg.Answer[i] = aRecord
			modified = true
			hm.logger.Printf("Hijacked DNS response for %s: %s -> %s", queryDomain, oldIP, hijackIP)
		}
	}

	return modified
}

// Save 保存劫持规则到文件
func (hm *HijackManager) Save() error {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	rules := make([]HijackRule, 0, len(hm.rules))
	for domain, ipv4 := range hm.rules {
		rules = append(rules, HijackRule{
			Domain: domain,
			IPv4:   ipv4,
		})
	}

	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(hm.dataPath, "hijack_rules.json")
	return os.WriteFile(filePath, data, 0644)
}

// Load 从文件加载劫持规则
func (hm *HijackManager) Load() error {
	filePath := filepath.Join(hm.dataPath, "hijack_rules.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在是正常的（首次运行）
			return nil
		}
		return err
	}

	var rules []HijackRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()

	// 清空现有规则并加载新规则
	hm.rules = make(map[string]string, len(rules))
	for _, rule := range rules {
		domain := normalizeDomain(rule.Domain)
		hm.rules[domain] = rule.IPv4
	}

	hm.logger.Printf("Loaded %d hijack rules from disk", len(hm.rules))
	return nil
}
