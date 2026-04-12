package monitor

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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

// allowedDomains — SSRF protection: apenas domínios de plataformas de ingressos conhecidas.
// Sprint 2: impede que um atacante injete URLs arbitrárias via /admin/events
// para fazer o servidor realizar requests internos (SSRF).
var allowedDomains = []string{
	"ticketmaster.com.br",
	"eventim.com.br",
	"sympla.com.br",
	"ingresso.com",
	"blueticket.com.br",
	"tickets4fun.com.br",
}

// IsAllowedURL verifica se a URL pertence a um domínio da allowlist.
// Exportada para uso em main.go (validação no endpoint /admin/events).
// Proteção: normaliza o host para lowercase antes de comparar.
func IsAllowedURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	// Garante esquema HTTP/HTTPS — rejeita file://, ftp://, etc.
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

// Check faz uma requisição à página do evento e retorna o salesStatus.
// SSRF protection: valida o domínio da URL antes de realizar o request.
func Check(event Event, previous Status) (CheckResult, error) {
	// SSRF: rejeita URLs fora da allowlist antes de qualquer I/O
	if !IsAllowedURL(event.URL) {
		return CheckResult{}, fmt.Errorf("domínio não permitido: %s", event.URL)
	}

	req, err := http.NewRequest("GET", event.URL, nil)
	if err != nil {
		return CheckResult{}, fmt.Errorf("criar request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return CheckResult{}, fmt.Errorf("requisição http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // max 512KB
	if err != nil {
		return CheckResult{}, fmt.Errorf("ler body: %w", err)
	}

	status := extractStatus(string(body))

	// Debug temporário: logar quando retornar UNKNOWN para diagnóstico em produção
	if status == StatusUnknown {
		log.Printf("[DEBUG] %s: body=%dB, HTTP=%d, primeiros100=%q",
			event.Label, len(body), resp.StatusCode, string(body[:min(100, len(body))]))
	}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
