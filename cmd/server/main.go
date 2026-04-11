package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/victorgsrocha/ticketradar/internal/monitor"
	"github.com/victorgsrocha/ticketradar/internal/notify"
	"github.com/victorgsrocha/ticketradar/internal/store"
)

type Config struct {
	notify.Config
	Port          string
	DBPath        string
	Interval      time.Duration
	AllowedOrigin string // C2: origem explícita para CORS
	DeleteToken   string // C3: token para autorizar DELETE
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
			EmailFrom:     os.Getenv("EMAIL_FROM"),
			EmailPassword: os.Getenv("EMAIL_PASSWORD"),
			EmailTo:       os.Getenv("EMAIL_TO"),
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
	prev_count := int64(0)
	if v, ok := s.totalChecks.Load(event.URL); ok {
		prev_count = v.(int64)
	}
	s.totalChecks.Store(event.URL, prev_count+1)

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
		errs := notify.SendAll(s.cfg.Config, alert)
		for _, e := range errs {
			log.Printf("[%s] erro ao notificar: %v", event.Label, e)
		}
		if len(errs) == 0 {
			log.Printf("[%s] ✅ Alertas enviados!", event.Label)
		}
	}
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
		// CSP básico: só recursos próprios + Google Fonts
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"script-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'")
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

// chain encadeia múltiplos middlewares (aplicados de fora para dentro)
func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func waitlistHandler(db *store.DB, rl *rateLimiter, deleteToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// LGPD — Direito ao Esquecimento (Art. 18, IV)
		if r.Method == http.MethodDelete {
			// C3: DELETE requer token de autorização via header X-Delete-Token
			if deleteToken == "" || r.Header.Get("X-Delete-Token") != deleteToken {
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
			http.Error(w, `{"error":"json inválido"}`, http.StatusBadRequest)
			return
		}

		if body.Email == "" {
			http.Error(w, `{"error":"email obrigatório"}`, http.StatusBadRequest)
			return
		}

		// LGPD Art. 7 — base legal: consentimento
		if !body.ConsentTerms {
			http.Error(w, `{"error":"aceite dos termos obrigatório (LGPD Art. 7)"}`, http.StatusBadRequest)
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
func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			"waitlist_count":  waitlistCount,
			"total_checks":    totalChecks,
			"uptime_seconds":  uptimeSeconds,
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

	events := []monitor.Event{
		{ID: "bts-28", Label: "BTS 28/10", URL: "https://www.ticketmaster.com.br/event/venda-geral-bts-world-tour-arirang-28-10"},
		{ID: "bts-30", Label: "BTS 30/10", URL: "https://www.ticketmaster.com.br/event/venda-geral-bts-world-tour-arirang-30-10"},
		{ID: "bts-31", Label: "BTS 31/10", URL: "https://www.ticketmaster.com.br/event/venda-geral-bts-world-tour-arirang-31-10"},
	}

	// A3: rate limiter global — 5 requests/min por IP no /api/waitlist
	rl := newRateLimiter(5, 1*time.Minute)

	scheduler := &Scheduler{cfg: cfg, db: db, events: events, startedAt: time.Now()}
	go scheduler.run()

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./web")))
	mux.HandleFunc("/api/waitlist", waitlistHandler(db, rl, cfg.DeleteToken))
	mux.HandleFunc("/api/me", meHandler(db, cfg.DeleteToken))
	mux.HandleFunc("/api/status", statusHandler(scheduler))
	mux.HandleFunc("/health", healthHandler())
	mux.HandleFunc("/api/metrics", metricsHandler(scheduler))
	mux.HandleFunc("/api/history", historyHandler(db))

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
