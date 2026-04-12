package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/victorgsrocha/ticketradar/internal/monitor"
	"github.com/victorgsrocha/ticketradar/internal/notify"
	"github.com/victorgsrocha/ticketradar/internal/store"
)

// emailRegex valida formato de email — RFC 5321 simplificado.
// S1: impede persistência de dados claramente inválidos.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// whatsappRegex valida número de WhatsApp — apenas + e dígitos, 7–15 dígitos.
var whatsappRegex = regexp.MustCompile(`^\+?[0-9]{7,15}$`)

// htmlTagsRegex detecta tags HTML para sanitizar campos de texto livre.
var htmlTagsRegex = regexp.MustCompile(`[<>]`)

type Config struct {
	notify.Config
	Port          string
	DBPath        string
	Interval      time.Duration
	AllowedOrigin string // C2: origem explícita para CORS
	DeleteToken   string // C3: token para autorizar DELETE
	AdminUser     string // S2: usuário para Basic Auth das rotas admin
	AdminPass     string // S2: senha para Basic Auth das rotas admin (obrigatório em prod)
}

func loadConfig() Config {
	interval := 30 * time.Second
	if v := os.Getenv("CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}
	return Config{
		Config: notify.Config{
			ResendAPIKey: os.Getenv("RESEND_API_KEY"),
			EmailFrom:    os.Getenv("EMAIL_FROM"),
			EmailTo:      os.Getenv("EMAIL_TO"),
			TwilioSID:     os.Getenv("TWILIO_SID"),
			TwilioToken:   os.Getenv("TWILIO_TOKEN"),
			TwilioFrom:    os.Getenv("TWILIO_FROM"),
			TwilioTo:      os.Getenv("TWILIO_TO"),
		},
		Port:          getEnv("PORT", "8080"),
		DBPath:        getEnv("DB_PATH", "./ticketradar.db"),
		Interval:      interval,
		AllowedOrigin: os.Getenv("ALLOWED_ORIGIN"), // C2: vazio = sem CORS header
		DeleteToken:   os.Getenv("DELETE_TOKEN"),   // C3: obrigatório para DELETE
		AdminUser:     getEnv("ADMIN_USER", "admin"),
		AdminPass:     os.Getenv("ADMIN_PASS"), // S2: obrigatório em prod — vazio retorna 503
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────

// ipBucket rastreia requisições de um IP em uma janela deslizante de 1 minuto.
type ipBucket struct {
	count     int
	windowEnd time.Time
}

// rateLimiter implementa rate limit simples por IP com map + mutex.
// A3: protege /api/waitlist contra abuse/scraping.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
	max     int           // max requests por janela
	window  time.Duration // tamanho da janela
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*ipBucket),
		max:     max,
		window:  window,
	}
}

// allow retorna true se a requisição pode prosseguir, false se excedeu o limite.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok || now.After(b.windowEnd) {
		// Nova janela
		rl.buckets[ip] = &ipBucket{count: 1, windowEnd: now.Add(rl.window)}
		return true
	}
	if b.count >= rl.max {
		return false
	}
	b.count++
	return true
}

// extractIP extrai o IP real do request, considerando X-Forwarded-For (proxies/Railway).
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For pode ser "clientIP, proxy1, proxy2" — pegar o primeiro
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// RemoteAddr é "ip:port" — remover a porta
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// ── Email masking ─────────────────────────────────────────────────────────────

// maskEmail mascara o email para logs — "vic***@dominio.com".
// C5: evita exposição de PII em logs de produção (LGPD Art. 46).
func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "***"
	}
	local := parts[0]
	domain := parts[1]

	if len(local) <= 3 {
		return local + "***@" + domain
	}
	return local[:3] + "***@" + domain
}

// ── Input Validation ──────────────────────────────────────────────────────────

// validationError descreve um erro de validação com campo específico.
// S1: retorna 422 com campo e mensagem para que o cliente possa exibir feedback preciso.
type validationError struct {
	Field   string `json:"field"`
	Message string `json:"error"`
}

func (e *validationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// validateWaitlistInput valida os campos de entrada antes de persistir no banco.
// S1: impede XSS via HTML injection, emails malformados e números inválidos.
func validateWaitlistInput(name, email, whatsapp, categories string) *validationError {
	// Email: obrigatório, max 254 chars (RFC 5321), formato válido
	if utf8.RuneCountInString(email) > 254 {
		return &validationError{Field: "email", Message: "email muito longo (máx. 254 caracteres)"}
	}
	if !emailRegex.MatchString(email) {
		return &validationError{Field: "email", Message: "email inválido"}
	}

	// Name: max 100 chars, sem tags HTML
	if utf8.RuneCountInString(name) > 100 {
		return &validationError{Field: "name", Message: "nome muito longo (máx. 100 caracteres)"}
	}
	if htmlTagsRegex.MatchString(name) {
		return &validationError{Field: "name", Message: "nome contém caracteres não permitidos"}
	}

	// WhatsApp: opcional — se informado, valida formato
	if whatsapp != "" {
		if utf8.RuneCountInString(whatsapp) > 20 {
			return &validationError{Field: "whatsapp", Message: "whatsapp muito longo (máx. 20 caracteres)"}
		}
		if !whatsappRegex.MatchString(whatsapp) {
			return &validationError{Field: "whatsapp", Message: "whatsapp inválido (use formato +5511999999999)"}
		}
	}

	// Categories: max 200 chars
	if utf8.RuneCountInString(categories) > 200 {
		return &validationError{Field: "categories", Message: "categorias muito longas (máx. 200 caracteres)"}
	}

	return nil
}

// ── Scheduler ────────────────────────────────────────────────────────────────

type Scheduler struct {
	cfg         Config
	db          *store.DB
	events      []monitor.Event
	statuses    sync.Map
	totalChecks sync.Map // map[string]int64 por URL
	startedAt   time.Time
}

func (s *Scheduler) run() {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	// Purge a cada hora — C6: mantém status_log com no máximo 48h de dados
	purgeTicker := time.NewTicker(1 * time.Hour)
	defer purgeTicker.Stop()

	log.Printf("🎟️ TicketRadar iniciado — checando %d eventos a cada %s", len(s.events), s.cfg.Interval)
	s.checkAll()

	for {
		select {
		case <-ticker.C:
			s.checkAll()
		case <-purgeTicker.C:
			if err := s.db.PurgeOldStatusLogs(); err != nil {
				log.Printf("⚠️  erro ao purgar status_log: %v", err)
			}
		}
	}
}

func (s *Scheduler) checkAll() {
	for _, event := range s.events {
		go s.checkOne(event)
	}
}

func (s *Scheduler) checkOne(event monitor.Event) {
	prev := monitor.StatusUnknown
	if v, ok := s.statuses.Load(event.URL); ok {
		prev = v.(monitor.Status)
	}

	result, err := monitor.Check(event, prev)
	if err != nil {
		log.Printf("[%s] ⚠️  erro: %v", event.Label, err)
		return
	}

	s.statuses.Store(event.URL, result.Status)
	_ = s.db.LogStatus(event.URL, event.Label, string(result.Status))

	// Incrementa contador de checks
	prevCount := int64(0)
	if v, ok := s.totalChecks.Load(event.URL); ok {
		prevCount = v.(int64)
	}
	s.totalChecks.Store(event.URL, prevCount+1)

	icon := "❌"
	if result.Status.IsAvailable() {
		icon = "🟢"
	}
	log.Printf("[%s] %s %s", result.CheckedAt.Format("15:04:05"), icon, event.Label)

	if result.Status.IsAvailable() && result.Changed {
		log.Printf("[%s] 🚨 DISPONÍVEL! Disparando alertas...", event.Label)
		alert := notify.Alert{
			EventLabel: event.Label,
			EventURL:   event.URL,
			Status:     string(result.Status),
			DetectedAt: result.CheckedAt.Format("02/01 15:04:05"),
		}

		// Notifica o dono do sistema (Victor) por todos os canais
		errs := notify.SendAll(s.cfg.Config, alert)
		for _, e := range errs {
			log.Printf("[%s] erro ao notificar owner: %v", event.Label, e)
		}
		if len(errs) == 0 {
			log.Printf("[%s] ✅ Alertas owner enviados!", event.Label)
		}

		// Notifica TODOS os usuários da waitlist em goroutine separada
		go s.notifyWaitlist(event, alert)
	}
}

// notifyWaitlist envia alertas para todos os usuários da waitlist com deduplicação e rate limiting.
// Sprint 2: chamado em goroutine separada para não bloquear o loop principal do scheduler.
// Rate limiting: máx 10 envios simultâneos para não saturar o SMTP.
// Deduplicação: ignora usuários já alertados nas últimas 2h (evita spam em oscilações).
func (s *Scheduler) notifyWaitlist(event monitor.Event, alert notify.Alert) {
	emails, err := s.db.GetWaitlistEmails()
	if err != nil {
		log.Printf("erro ao buscar emails da waitlist: %v", err)
		return
	}

	if len(emails) == 0 {
		log.Printf("[%s] waitlist vazia — sem usuários para notificar", event.Label)
		return
	}

	log.Printf("[%s] 📢 notificando %d usuários da waitlist...", event.Label, len(emails))

	// Rate limiting de envio: máx 10 emails simultâneos — protege o SMTP
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, email := range emails {
		// Verificar deduplicação: não enviar se já alertou nas últimas 2h
		alerted, err := s.db.HasBeenAlerted(email, event.URL, 2)
		if err != nil {
			log.Printf("erro ao verificar alert_log: %v", err)
			continue
		}
		if alerted {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(toEmail string) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := notify.SendAllToUser(s.cfg.Config, toEmail, alert); err != nil {
				log.Printf("erro ao notificar %s: %v", maskEmail(toEmail), err)
				return
			}

			// Registrar no alert_log — base para deduplicação futura
			if err := s.db.RecordAlert(toEmail, event.URL); err != nil {
				log.Printf("erro ao registrar alert_log: %v", err)
			}

			log.Printf("[%s] ✅ alertado: %s", event.Label, maskEmail(toEmail))
		}(email)
	}

	wg.Wait()
	log.Printf("[%s] 📢 envio para waitlist concluído", event.Label)
}

// ── Middlewares ───────────────────────────────────────────────────────────────

// requestIDMiddleware injeta X-Request-ID em cada resposta.
// A4: permite rastreamento de erros client-side sem expor detalhes internos.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adiciona headers de segurança recomendados.
// M4: defesa em profundidade contra XSS, clickjacking e MIME sniffing.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Impede MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Bloqueia iframe embedding (clickjacking)
		w.Header().Set("X-Frame-Options", "DENY")
		// Não envia Referer para origens externas
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// HSTS: força HTTPS por 1 ano, inclui subdomínios
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// CSP básico: só recursos próprios + Google Fonts
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"script-src 'self' 'unsafe-inline' https://unpkg.com; "+
				"img-src 'self' data: https://unpkg.com; "+
				"connect-src 'self' https://ticketradar.com.br https://ticketradar-production-f6a4.up.railway.app; "+
				"worker-src blob:")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware restringe CORS para a origem configurada.
// C2: ALLOWED_ORIGIN deve ser definido em produção (ex: https://ticketradar.app).
// Se vazio, o header não é emitido — requests cross-origin serão bloqueados pelo browser.
func corsMiddleware(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Delete-Token, X-Request-ID")
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// basicAuthMiddlewareFn retorna um middleware que exige Basic Auth.
// S2: protege rotas internas sensíveis (/api/metrics, /api/history, /admin/events).
// Se ADMIN_PASS estiver vazio, retorna 503 com mensagem clara — fail-secure.
func basicAuthMiddlewareFn(adminUser, adminPass string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail-secure: se a senha não foi configurada, o endpoint é inacessível
			if adminPass == "" {
				http.Error(w, `{"error":"serviço indisponível — ADMIN_PASS não configurado"}`, http.StatusServiceUnavailable)
				return
			}
			user, pass, ok := r.BasicAuth()
			if !ok || user != adminUser || pass != adminPass {
				w.Header().Set("WWW-Authenticate", `Basic realm="TicketRadar Admin"`)
				http.Error(w, `{"error":"acesso restrito"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// protectedFileHandler envolve o FileServer e intercepta paths sensíveis,
// exigindo Basic Auth antes de servi-los.
// S2: impede acesso público ao dashboard.html, docs.html e openapi.yaml.
func protectedFileHandler(dir http.FileSystem, adminUser, adminPass string) http.Handler {
	fs := http.FileServer(dir)
	protected := map[string]bool{
		"/dashboard.html": true,
		"/docs.html":      true,
		"/openapi.yaml":   true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if protected[r.URL.Path] {
			// Fail-secure: sem senha configurada, o arquivo não é servido
			if adminPass == "" {
				http.Error(w, "Serviço indisponível — ADMIN_PASS não configurado", http.StatusServiceUnavailable)
				return
			}
			user, pass, ok := r.BasicAuth()
			if !ok || user != adminUser || pass != adminPass {
				w.Header().Set("WWW-Authenticate", `Basic realm="TicketRadar Admin"`)
				http.Error(w, "Acesso restrito", http.StatusUnauthorized)
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}

// chain encadeia múltiplos middlewares (aplicados de fora para dentro)
func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func waitlistHandler(db *store.DB, rl *rateLimiter, cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// LGPD — Direito ao Esquecimento (Art. 18, IV)
		if r.Method == http.MethodDelete {
			// C3: DELETE requer token de autorização via header X-Delete-Token
			if cfg.DeleteToken == "" || r.Header.Get("X-Delete-Token") != cfg.DeleteToken {
				http.Error(w, `{"error":"não autorizado"}`, http.StatusUnauthorized)
				return
			}

			email := r.URL.Query().Get("email")
			if email == "" {
				http.Error(w, `{"error":"email obrigatório"}`, http.StatusBadRequest)
				return
			}
			if err := db.DeleteFromWaitlist(email); err != nil {
				// C5: não loga o email em claro
				log.Printf("🗑️  erro ao deletar %s: %v", maskEmail(email), err)
				http.Error(w, `{"error":"erro interno"}`, http.StatusInternalServerError)
				return
			}
			// C5: log com email mascarado
			log.Printf("🗑️  LGPD: dados removidos para %s", maskEmail(email))
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "Dados removidos com sucesso."})
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"método não permitido"}`, http.StatusMethodNotAllowed)
			return
		}

		// A3: rate limit por IP — só no POST (cadastro), não no DELETE (exclusão LGPD)
		ip := extractIP(r)
		if !rl.allow(ip) {
			http.Error(w, `{"error":"muitas requisições, tente novamente em 1 minuto"}`, http.StatusTooManyRequests)
			return
		}

		// S3: limita body a 4KB para prevenir DoS por payload gigante
		r.Body = http.MaxBytesReader(w, r.Body, 4096)

		var body struct {
			Name       string `json:"name"`
			Email      string `json:"email"`
			WhatsApp   string `json:"whatsapp"`
			Categories string `json:"categories"`
			// LGPD — consentimento explícito obrigatório
			ConsentMarketing bool `json:"consent_marketing"`
			ConsentTerms     bool `json:"consent_terms"`
		}

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			// MaxBytesReader retorna erro específico quando o limite é excedido
			if err.Error() == "http: request body too large" {
				http.Error(w, `{"error":"payload muito grande (máx. 4KB)"}`, http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, `{"error":"json inválido"}`, http.StatusBadRequest)
			return
		}

		if body.Email == "" {
			http.Error(w, `{"error":"email obrigatório","field":"email"}`, http.StatusBadRequest)
			return
		}

		// LGPD Art. 7 — base legal: consentimento
		if !body.ConsentTerms {
			http.Error(w, `{"error":"aceite dos termos obrigatório (LGPD Art. 7)"}`, http.StatusBadRequest)
			return
		}

		// S1: validação de entrada antes de persistir
		if ve := validateWaitlistInput(body.Name, body.Email, body.WhatsApp, body.Categories); ve != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(ve)
			return
		}

		if err := db.AddToWaitlist(body.Name, body.Email, body.WhatsApp, body.Categories, body.ConsentMarketing); err != nil {
			// C5: não loga o email em claro
			log.Printf("erro ao salvar waitlist: %v", err)
			http.Error(w, `{"error":"erro interno"}`, http.StatusInternalServerError)
			return
		}

		count, _ := db.WaitlistCount()
		// C5: email mascarado no log
		log.Printf("📧 Novo cadastro: %s (%s) — total: %d", body.Name, maskEmail(body.Email), count)

		// Sprint 1: envia email de boas-vindas em background — não bloqueia a response
		go func() {
			if err := notify.SendWelcomeEmail(cfg.Config, body.Email, body.Name); err != nil {
				log.Printf("erro ao enviar email de boas-vindas para %s: %v", maskEmail(body.Email), err)
			}
		}()

		json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"message": "Você está na lista! Te avisamos quando lançar.",
			"total":   count,
		})
	}
}

// meHandler — LGPD portabilidade (Art. 18, II): GET /api/me?email=x&token=TOKEN
// M3: permite ao titular acessar seus próprios dados.
// Requer o mesmo DELETE_TOKEN como mecanismo de autorização simples.
func meHandler(db *store.DB, deleteToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"método não permitido"}`, http.StatusMethodNotAllowed)
			return
		}

		// Valida token — mesmo segredo do DELETE para simplicidade
		if deleteToken == "" || r.URL.Query().Get("token") != deleteToken {
			http.Error(w, `{"error":"não autorizado"}`, http.StatusUnauthorized)
			return
		}

		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, `{"error":"email obrigatório"}`, http.StatusBadRequest)
			return
		}

		entry, err := db.ExportUserData(email)
		if err != nil {
			log.Printf("erro ao exportar dados de %s: %v", maskEmail(email), err)
			http.Error(w, `{"error":"erro interno"}`, http.StatusInternalServerError)
			return
		}
		if entry == nil {
			http.Error(w, `{"error":"email não encontrado"}`, http.StatusNotFound)
			return
		}

		log.Printf("📤 LGPD portabilidade: exportado para %s", maskEmail(email))
		json.NewEncoder(w).Encode(map[string]any{
			"name":              entry.Name,
			"email":             entry.Email,
			"whatsapp":          entry.WhatsApp,
			"categories":        entry.Categories,
			"consent_marketing": entry.ConsentMarketing,
			"consent_terms":     entry.ConsentTerms,
			"consent_at":        entry.ConsentAt,
			"created_at":        entry.CreatedAt,
		})
	}
}

func statusHandler(s *Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := make(map[string]string)
		for _, event := range s.events {
			status := monitor.StatusUnknown
			if v, ok := s.statuses.Load(event.URL); ok {
				status = v.(monitor.Status)
			}
			result[event.Label] = string(status)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// healthHandler — para Railway/uptime checks
// Aceita apenas GET — métodos distintos retornam 405.
func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"método não permitido"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "1.0.0"})
	}
}

func metricsHandler(s *Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Total de checks somando todos os eventos
		var totalChecks int64
		s.totalChecks.Range(func(_, v any) bool {
			totalChecks += v.(int64)
			return true
		})

		waitlistCount, _ := s.db.WaitlistCount()
		uptimeSeconds := int64(time.Since(s.startedAt).Seconds())

		json.NewEncoder(w).Encode(map[string]any{
			"waitlist_count":   waitlistCount,
			"total_checks":     totalChecks,
			"uptime_seconds":   uptimeSeconds,
			"events_monitored": len(s.events),
		})
	}
}

func historyHandler(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		limit := 20
		if v := r.URL.Query().Get("limit"); v != "" {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 100 {
				limit = n
			}
		}

		entries, err := db.RecentStatusLogs(limit)
		if err != nil {
			http.Error(w, `{"error":"erro interno"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(entries)
	}
}

// adminEventsHandler gerencia os eventos monitorados via API REST.
// Sprint 2: permite adicionar/desativar eventos sem redeploy.
//
//	GET    /admin/events       — lista todos os eventos (ativos e inativos)
//	POST   /admin/events       — adiciona novo evento (com SSRF check obrigatório)
//	DELETE /admin/events?id=X  — desativa evento por ID (soft delete)
//
// Protegido por basicAuthMiddlewareFn — nunca expor sem ADMIN_PASS configurado.
func adminEventsHandler(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {

		case http.MethodGet:
			events, err := db.ListAllEvents()
			if err != nil {
				http.Error(w, `{"error":"erro interno"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(events)

		case http.MethodPost:
			// S3: limita body a 2KB
			r.Body = http.MaxBytesReader(w, r.Body, 2048)

			var body struct {
				Label    string `json:"label"`
				URL      string `json:"url"`
				Platform string `json:"platform"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"json inválido"}`, http.StatusBadRequest)
				return
			}

			if body.Label == "" || body.URL == "" {
				http.Error(w, `{"error":"label e url são obrigatórios"}`, http.StatusBadRequest)
				return
			}

			// SSRF protection: valida domínio antes de persistir — obrigatório
			if !monitor.IsAllowedURL(body.URL) {
				log.Printf("⚠️  tentativa de adicionar URL fora da allowlist: %s", body.URL)
				http.Error(w, `{"error":"domínio não permitido — apenas plataformas de ingressos conhecidas são aceitas"}`, http.StatusUnprocessableEntity)
				return
			}

			if err := db.AddEvent(body.Label, body.URL, body.Platform); err != nil {
				log.Printf("erro ao adicionar evento: %v", err)
				http.Error(w, `{"error":"erro interno — possivelmente URL duplicada"}`, http.StatusInternalServerError)
				return
			}

			log.Printf("🎟️  admin: evento adicionado — %q (%s)", body.Label, body.URL)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "Evento adicionado com sucesso."})

		case http.MethodDelete:
			idStr := r.URL.Query().Get("id")
			if idStr == "" {
				http.Error(w, `{"error":"parâmetro id obrigatório"}`, http.StatusBadRequest)
				return
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				http.Error(w, `{"error":"id inválido"}`, http.StatusBadRequest)
				return
			}
			if err := db.DeactivateEvent(id); err != nil {
				log.Printf("erro ao desativar evento id=%d: %v", id, err)
				http.Error(w, `{"error":"evento não encontrado ou erro interno"}`, http.StatusNotFound)
				return
			}
			log.Printf("🗑️  admin: evento id=%d desativado", id)
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "Evento desativado."})

		default:
			http.Error(w, `{"error":"método não permitido"}`, http.StatusMethodNotAllowed)
		}
	}
}

func main() {
	cfg := loadConfig()

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("abrir banco: %v", err)
	}
	defer db.Close()

	if cfg.DeleteToken == "" {
		log.Println("⚠️  AVISO: DELETE_TOKEN não definido — endpoint DELETE /api/waitlist retornará 401 sempre")
	}
	if cfg.AllowedOrigin == "" {
		log.Println("⚠️  AVISO: ALLOWED_ORIGIN não definido — CORS headers não serão emitidos")
	}
	if cfg.AdminPass == "" {
		log.Println("⚠️  AVISO: ADMIN_PASS não definido — rotas admin retornarão 503 (fail-secure)")
	}

	// Sprint 2: eventos padrão BTS — seed no banco se ainda não existirem
	defaultEvents := []monitor.Event{
		{ID: "bts-28", Label: "BTS 28/10", URL: "https://www.ticketmaster.com.br/event/venda-geral-bts-world-tour-arirang-28-10"},
		{ID: "bts-30", Label: "BTS 30/10", URL: "https://www.ticketmaster.com.br/event/venda-geral-bts-world-tour-arirang-30-10"},
		{ID: "bts-31", Label: "BTS 31/10", URL: "https://www.ticketmaster.com.br/event/venda-geral-bts-world-tour-arirang-31-10"},
	}
	if err := db.SeedDefaultEvents(defaultEvents); err != nil {
		log.Printf("⚠️  erro ao seed events: %v", err)
	}

	// Sprint 2: carrega eventos ativos do banco ao invés de lista hardcoded
	events, err := db.GetActiveEvents()
	if err != nil || len(events) == 0 {
		log.Printf("⚠️  usando eventos padrão (banco vazio ou erro: %v)", err)
		events = defaultEvents
	}

	// A3: rate limiter global — 5 requests/min por IP no /api/waitlist
	rl := newRateLimiter(5, 1*time.Minute)

	scheduler := &Scheduler{cfg: cfg, db: db, events: events, startedAt: time.Now()}
	go scheduler.run()

	// Middleware de Basic Auth para rotas de API internas
	adminAuth := basicAuthMiddlewareFn(cfg.AdminUser, cfg.AdminPass)

	mux := http.NewServeMux()

	// FileServer com proteção para arquivos sensíveis
	mux.Handle("/", protectedFileHandler(http.Dir("./web"), cfg.AdminUser, cfg.AdminPass))

	// Rotas públicas
	mux.HandleFunc("/api/waitlist", waitlistHandler(db, rl, cfg))
	mux.HandleFunc("/api/me", meHandler(db, cfg.DeleteToken))
	mux.HandleFunc("/api/status", statusHandler(scheduler))
	mux.HandleFunc("/health", healthHandler())

	// Rotas internas protegidas por Basic Auth
	mux.Handle("/api/metrics", adminAuth(http.HandlerFunc(metricsHandler(scheduler))))
	mux.Handle("/api/history", adminAuth(http.HandlerFunc(historyHandler(db))))

	// Sprint 2: endpoint admin para gerenciar eventos (CRUD com SSRF protection)
	mux.Handle("/admin/events", adminAuth(http.HandlerFunc(adminEventsHandler(db))))

	// Middlewares encadeados (ordem de aplicação: requestID → security headers → CORS → handler)
	handler := chain(
		mux,
		requestIDMiddleware,
		securityHeadersMiddleware,
		corsMiddleware(cfg.AllowedOrigin),
	)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("🌐 Servidor rodando em http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}
