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
	"github.com/victorgsrocha/ticketradar/internal/logger"
	"github.com/victorgsrocha/ticketradar/internal/metrics"
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
	metrics     *metrics.Metrics
}

func (s *Scheduler) run() {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	// Purge a cada hora — C6: mantém status_log com no máximo 48h de dados
	purgeTicker := time.NewTicker(1 * time.Hour)
	defer purgeTicker.Stop()

	// Pré-carregar último status conhecido do banco para evitar UNKNOWN no startup
	// Crítico: se o WAF bloqueia no primeiro check, preservamos o estado anterior
	s.preloadStatusesFromDB()

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

// preloadStatusesFromDB carrega o último status conhecido de cada evento do banco.
// Evita que /api/status retorne UNKNOWN no startup quando o WAF bloqueia os primeiros checks.
func (s *Scheduler) preloadStatusesFromDB() {
	for _, event := range s.events {
		last, err := s.db.LastStatusForEvent(event.URL)
		if err != nil || last == "" {
			continue
		}
		s.statuses.Store(event.URL, monitor.Status(last))
		log.Printf("[startup] %s: status inicial carregado do banco: %s", event.Label, last)
	}
}

func (s *Scheduler) checkAll() {
	for _, event := range s.events {
		go s.checkOne(event)
	}
}

func (s *Scheduler) checkOne(event monitor.Event) {
	start := time.Now()
	prev := monitor.StatusUnknown
	if v, ok := s.statuses.Load(event.URL); ok {
		prev = v.(monitor.Status)
	}

	result, err := monitor.Check(event, prev)
	elapsed := time.Since(start).Seconds()

	// Métricas de duração do check
	if s.metrics != nil {
		s.metrics.MonitorCheckDuration.WithLabelValues(event.Label).Observe(elapsed)
	}

	if err != nil {
		log.Printf("[%s] ⚠️  erro: %v", event.Label, err)
		if s.metrics != nil {
			s.metrics.MonitorChecksTotal.WithLabelValues(event.Label, "error").Inc()
		}
		return
	}

	s.statuses.Store(event.URL, result.Status)
	_ = s.db.LogStatus(event.URL, event.Label, string(result.Status))

	// Incrementa contador de checks e métricas
	prevCount := int64(0)
	if v, ok := s.totalChecks.Load(event.URL); ok {
		prevCount = v.(int64)
	}
	s.totalChecks.Store(event.URL, prevCount+1)

	if s.metrics != nil {
		s.metrics.MonitorChecksTotal.WithLabelValues(event.Label, string(result.Status)).Inc()
	}

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
			if s.metrics != nil {
				s.metrics.AlertsErrorTotal.WithLabelValues("all").Inc()
			}
		}
		if len(errs) == 0 {
			log.Printf("[%s] ✅ Alertas owner enviados!", event.Label)
			if s.metrics != nil {
				s.metrics.AlertsSentTotal.WithLabelValues("owner", event.Label).Inc()
			}
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

// ── DB Admin Handlers ────────────────────────────────────────────────────────

// adminDBUIHandler serve a interface web do DB Admin.
// Protegido por Basic Auth — acessa o banco SQLite de produção.
func adminDBUIHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dbAdminHTML))
	}
}

// adminDBQueryHandler executa uma query SQL somente-leitura.
func adminDBQueryHandler(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"método não permitido"}`, http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Query == "" {
			http.Error(w, `{"error":"query obrigatória"}`, http.StatusBadRequest)
			return
		}
		result, err := db.AdminQuery(body.Query)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(result)
	}
}

// adminDBTablesHandler lista todas as tabelas do banco com contagem de linhas.
func adminDBTablesHandler(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tables, err := db.AdminQuery(
			"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
		if err != nil {
			http.Error(w, `{"error":"erro ao listar tabelas"}`, http.StatusInternalServerError)
			return
		}
		// Para cada tabela, pegar o COUNT(*)
		type tableInfo struct {
			Name  string `json:"name"`
			Rows  int64  `json:"rows"`
		}
		var result []tableInfo
		for _, row := range tables.Rows {
			name := fmt.Sprintf("%v", row[0])
			countResult, err := db.AdminQuery("SELECT COUNT(*) FROM " + name)
			count := int64(0)
			if err == nil && len(countResult.Rows) > 0 && len(countResult.Rows[0]) > 0 {
				switch v := countResult.Rows[0][0].(type) {
				case int64:
					count = v
				case float64:
					count = int64(v)
				}
			}
			result = append(result, tableInfo{Name: name, Rows: count})
		}
		json.NewEncoder(w).Encode(result)
	}
}

// dbAdminHTML é a interface web embutida do DB Admin.
// Single-file HTML com editor SQL, resultados em tabela, atalhos de tabelas.
const dbAdminHTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TicketRadar — DB Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0D0D0D;--bg2:#141414;--bg3:#1A1A1A;--border:rgba(255,255,255,0.08);--text:#F0F0F5;--muted:#8B8FA3;--primary:#FF4B6E;--success:#06D6A0;--warn:#FFD166;--font-mono:'JetBrains Mono',monospace}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;height:100vh;display:flex;flex-direction:column}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:12px;flex-shrink:0}
header h1{font-size:.95rem;font-weight:700;letter-spacing:-.01em}
header .badge{background:rgba(255,75,110,.15);color:var(--primary);border:1px solid rgba(255,75,110,.3);border-radius:4px;padding:2px 8px;font-size:.7rem;font-weight:700}
.layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:200px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.sidebar h2{font-size:.7rem;font-weight:700;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;padding:12px 14px 8px}
.table-list{overflow-y:auto;flex:1}
.table-item{padding:7px 14px;cursor:pointer;font-size:.8rem;color:var(--muted);display:flex;justify-content:space-between;align-items:center;border-radius:4px;margin:1px 6px;transition:.15s}
.table-item:hover{background:var(--bg3);color:var(--text)}
.table-item .count{font-size:.7rem;background:var(--bg3);border-radius:3px;padding:1px 5px}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.editor-area{padding:12px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:8px;flex-shrink:0}
.editor-row{display:flex;gap:8px;align-items:flex-end}
textarea{flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--font-mono);font-size:.8rem;line-height:1.5;padding:10px 12px;resize:vertical;min-height:80px;outline:none;transition:.15s}
textarea:focus{border-color:var(--primary)}
.btn{background:var(--primary);color:#fff;border:none;cursor:pointer;padding:8px 18px;border-radius:6px;font-family:inherit;font-size:.82rem;font-weight:600;white-space:nowrap;transition:.15s;height:36px}
.btn:hover{opacity:.85}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-ghost{background:var(--bg3);border:1px solid var(--border);color:var(--muted)}
.btn-ghost:hover{color:var(--text);border-color:rgba(255,255,255,.2)}
.shortcuts{display:flex;gap:6px;flex-wrap:wrap}
.shortcut{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:3px 8px;font-size:.72rem;color:var(--muted);cursor:pointer;font-family:var(--font-mono);transition:.15s}
.shortcut:hover{color:var(--text);border-color:var(--primary)}
.result-area{flex:1;overflow:auto;padding:12px}
.meta{font-size:.72rem;color:var(--muted);margin-bottom:8px;display:flex;gap:16px}
.meta span{display:flex;align-items:center;gap:4px}
.meta .ok{color:var(--success)}
.meta .err{color:var(--primary)}
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{background:var(--bg3);color:var(--muted);font-weight:600;text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);font-size:.7rem;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap;position:sticky;top:0}
td{padding:6px 10px;border-bottom:1px solid rgba(255,255,255,.04);color:var(--text);font-family:var(--font-mono);font-size:.77rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:var(--bg3)}
.null{color:var(--muted);font-style:italic}
.empty{text-align:center;padding:40px;color:var(--muted);font-size:.85rem}
.error-box{background:rgba(255,75,110,.1);border:1px solid rgba(255,75,110,.3);border-radius:6px;padding:12px;color:var(--primary);font-size:.82rem;margin-bottom:8px;font-family:var(--font-mono)}
</style>
</head>
<body>
<header>
  <span>🎟️</span>
  <h1>TicketRadar — DB Admin</h1>
  <span class="badge">PRODUCTION</span>
  <span style="color:var(--muted);font-size:.75rem;margin-left:auto">Apenas SELECT permitido</span>
</header>
<div class="layout">
  <aside class="sidebar">
    <h2>Tabelas</h2>
    <div class="table-list" id="tableList"><div class="empty">Carregando...</div></div>
  </aside>
  <div class="main">
    <div class="editor-area">
      <div class="shortcuts" id="shortcuts">
        <span class="shortcut" onclick="setQuery('SELECT * FROM waitlist ORDER BY created_at DESC LIMIT 50')">waitlist</span>
        <span class="shortcut" onclick="setQuery('SELECT COUNT(*) as total, COUNT(CASE WHEN consent_marketing=1 THEN 1 END) as marketing FROM waitlist')">waitlist stats</span>
        <span class="shortcut" onclick="setQuery('SELECT event_label, status, logged_at FROM status_log ORDER BY logged_at DESC LIMIT 100')">status log</span>
        <span class="shortcut" onclick="setQuery('SELECT action, email_hash, logged_at FROM lgpd_audit ORDER BY logged_at DESC LIMIT 50')">audit LGPD</span>
        <span class="shortcut" onclick="setQuery('SELECT id, label, url, platform, active FROM events ORDER BY id')">events</span>
        <span class="shortcut" onclick="setQuery('SELECT event_url, COUNT(*) as alerts, MAX(alerted_at) as last FROM alert_log GROUP BY event_url')">alert log</span>
      </div>
      <div class="editor-row">
        <textarea id="query" placeholder="SELECT * FROM waitlist LIMIT 10;" spellcheck="false"></textarea>
        <div style="display:flex;flex-direction:column;gap:6px">
          <button class="btn" id="runBtn" onclick="runQuery()">▶ Executar</button>
          <button class="btn btn-ghost" onclick="clearResult()">Limpar</button>
        </div>
      </div>
    </div>
    <div class="result-area" id="result">
      <div class="empty">Execute uma query para ver os resultados.</div>
    </div>
  </div>
</div>
<script>
const queryEl = document.getElementById('query');
const resultEl = document.getElementById('result');
const runBtn = document.getElementById('runBtn');

// Ctrl+Enter executa
queryEl.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runQuery();
});

function setQuery(q) {
  queryEl.value = q;
  queryEl.focus();
}

function clearResult() {
  resultEl.innerHTML = '<div class="empty">Execute uma query para ver os resultados.</div>';
}

async function runQuery() {
  const q = queryEl.value.trim();
  if (!q) return;
  runBtn.disabled = true;
  runBtn.textContent = '⏳ Executando...';
  resultEl.innerHTML = '';
  try {
    const r = await fetch('/admin/db/query', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({query: q})
    });
    const data = await r.json();
    if (!r.ok || data.error) {
      resultEl.innerHTML = '<div class="error-box">⚠️ ' + (data.error || 'Erro desconhecido') + '</div>';
      return;
    }
    renderResult(data);
  } catch(e) {
    resultEl.innerHTML = '<div class="error-box">⚠️ Erro de rede: ' + e.message + '</div>';
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = '▶ Executar';
  }
}

function renderResult(data) {
  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.innerHTML = '<span class="ok">✓ ' + data.row_count + ' linhas</span>' +
    '<span>' + data.duration_ms + 'ms</span>' +
    '<span>' + data.columns.length + ' colunas</span>';
  resultEl.appendChild(meta);

  if (data.row_count === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'Nenhuma linha retornada.';
    resultEl.appendChild(empty);
    return;
  }

  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  data.columns.forEach(col => {
    const th = document.createElement('th');
    th.textContent = col;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  data.rows.forEach(row => {
    const tr = document.createElement('tr');
    row.forEach(val => {
      const td = document.createElement('td');
      if (val === null || val === undefined) {
        td.innerHTML = '<span class="null">NULL</span>';
      } else {
        td.textContent = String(val);
        td.title = String(val);
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  resultEl.appendChild(table);
}

// Carregar tabelas
async function loadTables() {
  try {
    const r = await fetch('/admin/db/tables');
    const tables = await r.json();
    const list = document.getElementById('tableList');
    list.innerHTML = '';
    tables.forEach(t => {
      const item = document.createElement('div');
      item.className = 'table-item';
      item.innerHTML = '<span>' + t.name + '</span><span class="count">' + t.rows + '</span>';
      item.onclick = () => setQuery('SELECT * FROM ' + t.name + ' ORDER BY rowid DESC LIMIT 50');
      list.appendChild(item);
    });
  } catch(e) {
    document.getElementById('tableList').innerHTML = '<div class="empty">Erro ao carregar</div>';
  }
}

loadTables();
</script>
</body>
</html>`

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
	// Fase 0.2: Setup de logging — Better Stack se BETTERSTACK_TOKEN estiver configurado
	cleanup := logger.Setup()
	defer cleanup()

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

	scheduler := &Scheduler{cfg: cfg, db: db, events: events, startedAt: time.Now(), metrics: nil}
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

	// Fase 1: /metrics — Prometheus format, protegido por Basic Auth
	m := metrics.New()
	scheduler.metrics = m
	mux.Handle("/metrics", adminAuth(m.Handler()))

	// Rotas internas protegidas por Basic Auth
	mux.Handle("/api/metrics", adminAuth(http.HandlerFunc(metricsHandler(scheduler))))
	mux.Handle("/api/history", adminAuth(http.HandlerFunc(historyHandler(db))))

	// Sprint 2: endpoint admin para gerenciar eventos (CRUD com SSRF protection)
	mux.Handle("/admin/events", adminAuth(http.HandlerFunc(adminEventsHandler(db))))

	// Fase 0.1: DB Admin — acesso seguro ao banco via browser
	mux.Handle("/admin/db", adminAuth(http.HandlerFunc(adminDBUIHandler())))
	mux.Handle("/admin/db/query", adminAuth(http.HandlerFunc(adminDBQueryHandler(db))))
	mux.Handle("/admin/db/tables", adminAuth(http.HandlerFunc(adminDBTablesHandler(db))))

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
