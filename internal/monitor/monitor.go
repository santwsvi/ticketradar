package monitor

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// Status representa o estado de disponibilidade de um evento
type Status string

const (
	StatusSoldOut   Status = "SOLD_OUT"
	StatusInSale    Status = "IN_SALE"
	StatusOnSale    Status = "ON_SALE"
	StatusPreSale   Status = "PRE_SALE"
	StatusAvailable Status = "AVAILABLE"
	StatusUnknown   Status = "UNKNOWN"
)

// IsAvailable retorna true para qualquer status que signifique ingresso disponível
func (s Status) IsAvailable() bool {
	switch s {
	case StatusInSale, StatusOnSale, StatusPreSale, StatusAvailable:
		return true
	}
	return false
}

// Event representa um evento monitorado
type Event struct {
	ID    string
	Label string
	URL   string
}

// CheckResult é o resultado de uma verificação
type CheckResult struct {
	Event     Event
	Status    Status
	CheckedAt time.Time
	Changed   bool // true se mudou em relação ao check anterior
}

var (
	salesStatusRe = regexp.MustCompile(`"salesStatus"\s*:\s*"([^"]+)"`)
	httpClient    = &http.Client{Timeout: 15 * time.Second}
)

// allowedDomains — SSRF protection
var allowedDomains = []string{
	"ticketmaster.com.br",
	"eventim.com.br",
	"sympla.com.br",
	"ingresso.com",
	"blueticket.com.br",
	"tickets4fun.com.br",
}

// IsAllowedURL verifica se a URL pertence a um domínio da allowlist.
func IsAllowedURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	for _, domain := range allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// userAgents para rotacionar entre requests e reduzir bot fingerprinting.
var userAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
}

var uaCounter int64

func nextUserAgent() string {
	idx := atomic.AddInt64(&uaCounter, 1) % int64(len(userAgents))
	return userAgents[idx]
}

// Check faz uma requisição à página do evento e retorna o salesStatus.
// Trata 403 (WAF/bot protection) sem propagar como erro — retorna UNKNOWN sem alterar o status anterior.
func Check(event Event, previous Status) (CheckResult, error) {
	if !IsAllowedURL(event.URL) {
		return CheckResult{}, fmt.Errorf("domínio não permitido: %s", event.URL)
	}

	req, err := http.NewRequest("GET", event.URL, nil)
	if err != nil {
		return CheckResult{}, fmt.Errorf("criar request: %w", err)
	}

	// Headers que imitam um browser real para reduzir bloqueio por WAF
	req.Header.Set("User-Agent", nextUserAgent())
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return CheckResult{}, fmt.Errorf("requisição http: %w", err)
	}
	defer resp.Body.Close()

	// 403 / 429 = WAF ou rate limit — não é falha do código, não alterar status anterior
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		log.Printf("[MONITOR] %s: bloqueado pelo WAF (HTTP %d) — mantendo status anterior (%s)",
			event.Label, resp.StatusCode, previous)
		return CheckResult{
			Event:     event,
			Status:    previous, // preserva o último status conhecido
			CheckedAt: time.Now(),
			Changed:   false,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return CheckResult{}, fmt.Errorf("HTTP %d inesperado", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return CheckResult{}, fmt.Errorf("ler body: %w", err)
	}

	status := extractStatus(string(body))
	result := CheckResult{
		Event:     event,
		Status:    status,
		CheckedAt: time.Now(),
		Changed:   status != previous && previous != StatusUnknown,
	}

	return result, nil
}

// extractStatus extrai o salesStatus do HTML/JSON da página
func extractStatus(body string) Status {
	matches := salesStatusRe.FindStringSubmatch(body)
	if len(matches) < 2 {
		return StatusUnknown
	}

	raw := strings.ToUpper(strings.TrimSpace(matches[1]))
	switch raw {
	case "IN_SALE":
		return StatusInSale
	case "ON_SALE", "ONSALE":
		return StatusOnSale
	case "PRE_SALE", "PRESALE":
		return StatusPreSale
	case "AVAILABLE":
		return StatusAvailable
	case "SOLD_OUT", "SOLDOUT":
		return StatusSoldOut
	default:
		return StatusUnknown
	}
}
