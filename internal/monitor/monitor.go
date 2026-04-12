package monitor

import (
	"encoding/json"
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

// CheckConfig contém configuração opcional do monitor
// (Worker proxy para fallback quando IP Railway é bloqueado).
type CheckConfig struct {
	// WorkerURL: URL base do Cloudflare Worker proxy
	// Ex: "https://monitor.ticketradar.com.br"
	// Se vazio, o monitor acessa a Ticketmaster diretamente.
	WorkerURL   string
	WorkerToken string
}

var (
	salesStatusRe = regexp.MustCompile(`"salesStatus"\s*:\s*"([^"]+)"`)
	// DisableCompression: força resposta não comprimida.
	// A Ticketmaster com gzip retorna o salesStatus além de 30KB — que é cortado pelo LimitReader.
	// Sem compressão, a resposta completa (~169KB) chega de uma vez e o salesStatus é encontrado.
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}
	workerClient = &http.Client{Timeout: 20 * time.Second}
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
// B2: se WorkerURL estiver configurado, usa o Cloudflare Worker como proxy
//     (IP do edge Cloudflare em vez do IP fixo do Railway — evita bloqueio WAF).
//     Se o Worker falhar ou retornar blocked, faz fallback para acesso direto.
func Check(event Event, previous Status) (CheckResult, error) {
	return CheckWithConfig(event, previous, CheckConfig{})
}

// CheckWithConfig permite passar configuração do Worker proxy.
func CheckWithConfig(event Event, previous Status, cfg CheckConfig) (CheckResult, error) {
	if !IsAllowedURL(event.URL) {
		return CheckResult{}, fmt.Errorf("domínio não permitido: %s", event.URL)
	}

	// B2: tentar via Worker primeiro se configurado
	if cfg.WorkerURL != "" && cfg.WorkerToken != "" {
		result, err := checkViaWorker(event, previous, cfg)
		if err == nil && result.Status != StatusUnknown {
			return result, nil
		}
		// Fallback silencioso para acesso direto
		log.Printf("[MONITOR] %s: Worker falhou (%v), tentando acesso direto", event.Label, err)
	}

	return checkDirect(event, previous)
}

// checkViaWorker consulta o Cloudflare Worker proxy
func checkViaWorker(event Event, previous Status, cfg CheckConfig) (CheckResult, error) {
	workerURL := fmt.Sprintf("%s/check?url=%s", cfg.WorkerURL, event.URL)
	req, err := http.NewRequest("GET", workerURL, nil)
	if err != nil {
		return CheckResult{}, err
	}
	req.Header.Set("X-Worker-Token", cfg.WorkerToken)

	resp, err := workerClient.Do(req)
	if err != nil {
		return CheckResult{}, fmt.Errorf("worker request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CheckResult{}, fmt.Errorf("worker retornou HTTP %d", resp.StatusCode)
	}

	var workerResp struct {
		SalesStatus *string `json:"salesStatus"`
		HTTPStatus  int     `json:"httpStatus"`
		Blocked     bool    `json:"blocked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&workerResp); err != nil {
		return CheckResult{}, fmt.Errorf("decode worker response: %w", err)
	}

	if workerResp.Blocked {
		log.Printf("[MONITOR] %s: Worker também bloqueado (HTTP %d via edge)", event.Label, workerResp.HTTPStatus)
		return CheckResult{
			Event:     event,
			Status:    previous,
			CheckedAt: time.Now(),
			Changed:   false,
		}, nil
	}

	if workerResp.SalesStatus == nil {
		return CheckResult{}, fmt.Errorf("worker: salesStatus não encontrado")
	}

	status := extractStatus(fmt.Sprintf(`"salesStatus":"%s"`, *workerResp.SalesStatus))
	return CheckResult{
		Event:     event,
		Status:    status,
		CheckedAt: time.Now(),
		Changed:   status != previous && previous != StatusUnknown,
	}, nil
}

// checkDirect acessa a Ticketmaster diretamente (fallback)
func checkDirect(event Event, previous Status) (CheckResult, error) {

	req, err := http.NewRequest("GET", event.URL, nil)
	if err != nil {
		return CheckResult{}, fmt.Errorf("criar request: %w", err)
	}

	// Headers que imitam um browser real — sem Accept-Encoding
	// (evita gzip que corta o body antes do salesStatus)
	req.Header.Set("User-Agent", nextUserAgent())
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
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
