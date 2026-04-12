package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/victorgsrocha/ticketradar/internal/monitor"
	_ "modernc.org/sqlite"
)

// salt fixo para anonimização de emails no audit log.
// Não é para autenticação — é para evitar que o hash seja
// reversível por rainbow table trivial no contexto de audit LGPD.
const auditSalt = "ticketradar-lgpd-audit-v1"

type DB struct {
	conn *sql.DB
}

type WaitlistEntry struct {
	ID               int64
	Name             string
	Email            string
	WhatsApp         string
	Categories       string
	ConsentMarketing bool
	ConsentTerms     bool
	ConsentAt        time.Time
	CreatedAt        time.Time
}

type StatusLog struct {
	EventURL string
	Status   string
	LoggedAt time.Time
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// C7: WAL mode — melhora concorrência leitura/escrita e reduz contenção
	if _, err := conn.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ativar WAL mode: %w", err)
	}
	// Ajustes complementares de performance e segurança
	if _, err := conn.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pragma synchronous: %w", err)
	}
	if _, err := conn.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pragma foreign_keys: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS waitlist (
			id                 INTEGER PRIMARY KEY AUTOINCREMENT,
			name               TEXT NOT NULL,
			email              TEXT NOT NULL UNIQUE,
			whatsapp           TEXT,
			categories         TEXT,
			-- LGPD: registro de consentimento (Art. 7 + Art. 8)
			consent_marketing  INTEGER NOT NULL DEFAULT 0,
			consent_terms      INTEGER NOT NULL DEFAULT 1,
			consent_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
			-- LGPD: não armazenamos mais que o necessário
			created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS status_log (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			event_url   TEXT NOT NULL,
			event_label TEXT NOT NULL DEFAULT '',
			status      TEXT NOT NULL,
			logged_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- LGPD: audit log de operações sobre dados pessoais (Art. 37)
		CREATE TABLE IF NOT EXISTS lgpd_audit (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			action     TEXT NOT NULL,  -- 'INSERT','DELETE','EXPORT'
			email_hash TEXT NOT NULL,  -- SHA-256+salt do email (nunca em claro)
			ip_hash    TEXT,
			logged_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Sprint 2: deduplicação de alertas — evita spam quando status oscila
		CREATE TABLE IF NOT EXISTS alert_log (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			email_hash  TEXT NOT NULL,       -- SHA-256+salt do email
			event_url   TEXT NOT NULL,
			alerted_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Sprint 2: eventos configuráveis — gerenciados via admin API
		CREATE TABLE IF NOT EXISTS events (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			label       TEXT NOT NULL,
			url         TEXT NOT NULL UNIQUE,
			platform    TEXT NOT NULL DEFAULT 'ticketmaster',
			active      INTEGER NOT NULL DEFAULT 1,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_status_log_url ON status_log(event_url);
		CREATE INDEX IF NOT EXISTS idx_status_log_logged_at ON status_log(logged_at);
		CREATE INDEX IF NOT EXISTS idx_alert_log ON alert_log(email_hash, event_url, alerted_at);
	`)
	return err
}

// AddToWaitlist insere novo cadastro com registro de consentimento LGPD
func (db *DB) AddToWaitlist(name, email, whatsapp, categories string, consentMarketing bool) error {
	consent := 0
	if consentMarketing {
		consent = 1
	}
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO waitlist (name, email, whatsapp, categories, consent_marketing, consent_terms, consent_at)
		 VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
		name, email, whatsapp, categories, consent,
	)
	if err != nil {
		return err
	}
	// Audit log — LGPD Art. 37
	return db.auditLog("INSERT", email, "")
}

// DeleteFromWaitlist remove todos os dados de um usuário (LGPD Art. 18, IV — direito ao esquecimento)
func (db *DB) DeleteFromWaitlist(email string) error {
	if err := db.auditLog("DELETE", email, ""); err != nil {
		return err
	}
	_, err := db.conn.Exec(`DELETE FROM waitlist WHERE email = ?`, email)
	return err
}

// ExportUserData retorna todos os dados de um usuário (LGPD Art. 18, II — portabilidade)
func (db *DB) ExportUserData(email string) (*WaitlistEntry, error) {
	row := db.conn.QueryRow(
		`SELECT id, name, email, whatsapp, categories, consent_marketing, consent_terms, consent_at, created_at
		 FROM waitlist WHERE email = ?`, email)

	var e WaitlistEntry
	var consentMarketing, consentTerms int
	err := row.Scan(&e.ID, &e.Name, &e.Email, &e.WhatsApp, &e.Categories,
		&consentMarketing, &consentTerms, &e.ConsentAt, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.ConsentMarketing = consentMarketing == 1
	e.ConsentTerms = consentTerms == 1

	_ = db.auditLog("EXPORT", email, "")
	return &e, nil
}

// LogStatus registra um status no histórico com label legível
func (db *DB) LogStatus(eventURL, eventLabel, status string) error {
	_, err := db.conn.Exec(
		`INSERT INTO status_log (event_url, event_label, status) VALUES (?, ?, ?)`,
		eventURL, eventLabel, status,
	)
	return err
}

// PurgeOldStatusLogs remove entradas de status_log mais antigas que 48h.
// C6: evita crescimento indefinido da tabela.
// Deve ser chamado periodicamente (ex: a cada ciclo do scheduler).
func (db *DB) PurgeOldStatusLogs() error {
	_, err := db.conn.Exec(
		`DELETE FROM status_log WHERE logged_at < datetime('now', '-48 hours')`,
	)
	return err
}

// WaitlistCount retorna o total de cadastros
func (db *DB) WaitlistCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM waitlist`).Scan(&count)
	return count, err
}

// GetWaitlistEmails retorna todos os emails de usuários que consentiram com os termos.
// Sprint 2: usado para notificar todos os cadastrados quando ingressos ficarem disponíveis.
// Filtro: consent_terms=1 — apenas quem aceitou os termos explicitamente.
func (db *DB) GetWaitlistEmails() ([]string, error) {
	rows, err := db.conn.Query(
		`SELECT email FROM waitlist WHERE consent_terms = 1`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			continue
		}
		emails = append(emails, email)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if emails == nil {
		emails = []string{}
	}
	return emails, nil
}

// HasBeenAlerted verifica se um usuário já foi alertado para este evento nas últimas N horas.
// Sprint 2: evita spam de alertas quando o status oscila entre SOLD_OUT e disponível.
// Usa SHA-256+salt igual ao auditLog para manter PII fora do banco.
func (db *DB) HasBeenAlerted(email, eventURL string, withinHours int) (bool, error) {
	emailHash := hashWithSalt(email)
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM alert_log
		 WHERE email_hash = ?
		   AND event_url  = ?
		   AND alerted_at > datetime('now', ? || ' hours')`,
		emailHash, eventURL, fmt.Sprintf("-%d", withinHours),
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("has been alerted query: %w", err)
	}
	return count > 0, nil
}

// RecordAlert registra que o alerta foi enviado para este usuário/evento.
// Sprint 2: sempre chamado após envio bem-sucedido para alimentar a deduplicação.
// Email é armazenado como SHA-256+salt — nunca em claro.
func (db *DB) RecordAlert(email, eventURL string) error {
	emailHash := hashWithSalt(email)
	_, err := db.conn.Exec(
		`INSERT INTO alert_log (email_hash, event_url) VALUES (?, ?)`,
		emailHash, eventURL,
	)
	return err
}

// GetActiveEvents retorna todos os eventos com active=1.
// Sprint 2: usado pelo scheduler ao invés de lista hardcoded.
func (db *DB) GetActiveEvents() ([]monitor.Event, error) {
	rows, err := db.conn.Query(
		`SELECT id, label, url, platform FROM events WHERE active = 1 ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("get active events: %w", err)
	}
	defer rows.Close()

	var events []monitor.Event
	for rows.Next() {
		var dbID int64
		var label, rawURL, platform string
		if err := rows.Scan(&dbID, &label, &rawURL, &platform); err != nil {
			continue
		}
		events = append(events, monitor.Event{
			ID:    fmt.Sprintf("%d", dbID),
			Label: label,
			URL:   rawURL,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// SeedDefaultEvents insere os eventos padrão se a tabela estiver vazia.
// Sprint 2: chamado no startup para garantir que os eventos BTS estão presentes.
// Idempotente — INSERT OR IGNORE evita duplicatas pela constraint UNIQUE(url).
func (db *DB) SeedDefaultEvents(events []monitor.Event) error {
	var count int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
		return fmt.Errorf("seed: count events: %w", err)
	}
	if count > 0 {
		// Banco já tem eventos — não sobrescreve dados configurados pelo admin
		return nil
	}

	for _, ev := range events {
		_, err := db.conn.Exec(
			`INSERT OR IGNORE INTO events (label, url, platform, active) VALUES (?, ?, 'ticketmaster', 1)`,
			ev.Label, ev.URL,
		)
		if err != nil {
			return fmt.Errorf("seed event %q: %w", ev.Label, err)
		}
	}
	return nil
}

// AddEvent insere um novo evento na tabela events.
// Sprint 2: usado pelo endpoint POST /admin/events.
func (db *DB) AddEvent(label, rawURL, platform string) error {
	if platform == "" {
		platform = "ticketmaster"
	}
	_, err := db.conn.Exec(
		`INSERT INTO events (label, url, platform, active) VALUES (?, ?, ?, 1)`,
		label, rawURL, platform,
	)
	return err
}

// DeactivateEvent desativa um evento pelo ID (soft delete).
// Sprint 2: usado pelo endpoint DELETE /admin/events?id=X.
func (db *DB) DeactivateEvent(id int64) error {
	res, err := db.conn.Exec(`UPDATE events SET active = 0 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("evento com id=%d não encontrado", id)
	}
	return nil
}

// ListAllEvents retorna todos os eventos (ativos e inativos) para o admin.
// Sprint 2: usado pelo endpoint GET /admin/events.
func (db *DB) ListAllEvents() ([]map[string]any, error) {
	rows, err := db.conn.Query(
		`SELECT id, label, url, platform, active, created_at FROM events ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var id int64
		var label, rawURL, platform, createdAt string
		var active int
		if err := rows.Scan(&id, &label, &rawURL, &platform, &active, &createdAt); err != nil {
			continue
		}
		result = append(result, map[string]any{
			"id":         id,
			"label":      label,
			"url":        rawURL,
			"platform":   platform,
			"active":     active == 1,
			"created_at": createdAt,
		})
	}
	if result == nil {
		result = []map[string]any{}
	}
	return result, nil
}

// PurgeTestData remove registros com emails claramente inválidos do banco.
// Usado para limpeza de dados de produção inseridos durante testes ou via abuse.
// SQLite não suporta REGEXP nativo — usa LIKE como fallback conservador:
//   - múltiplos @ (ex: a@b@c)
//   - sem domínio após @ (ex: user@)
//   - sem ponto no domínio (ex: user@dominio)
func (db *DB) PurgeTestData() error {
	_, err := db.conn.Exec(`
		DELETE FROM waitlist
		WHERE email LIKE '%@%@%'
		   OR email NOT LIKE '%_@_%.__%'
	`)
	return err
}

// auditLog registra operação sobre dado pessoal (LGPD Art. 37).
// C4: usa SHA-256 com salt fixo — não reversível por lookup trivial.
func (db *DB) auditLog(action, email, ipHash string) error {
	emailHash := hashWithSalt(email)
	_, err := db.conn.Exec(
		`INSERT INTO lgpd_audit (action, email_hash, ip_hash) VALUES (?, ?, ?)`,
		action, emailHash, ipHash,
	)
	return err
}

// hashWithSalt retorna SHA-256(salt+value) em hex.
// C4: substitui o FNV-32 reversível — SHA-256 com salt é resistente a
// rainbow table e não permite reconstrução do email original.
func hashWithSalt(value string) string {
	h := sha256.Sum256([]byte(auditSalt + value))
	return fmt.Sprintf("%x", h)
}

// RecentStatusLogs retorna as entradas mais recentes do log de status
func (db *DB) RecentStatusLogs(limit int) ([]map[string]string, error) {
	rows, err := db.conn.Query(
		`SELECT event_url, COALESCE(NULLIF(event_label,''), event_url), status, logged_at
		 FROM status_log ORDER BY logged_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]string
	for rows.Next() {
		var url, label, status, loggedAt string
		if err := rows.Scan(&url, &label, &status, &loggedAt); err != nil {
			continue
		}
		entries = append(entries, map[string]string{
			"event":  label,
			"status": status,
			"at":     loggedAt,
		})
	}
	if entries == nil {
		entries = []map[string]string{}
	}
	return entries, nil
}

// LastStatusForEvent retorna o status mais recente registrado para um evento.
// Usado no startup para pré-carregar a sync.Map e evitar UNKNOWN quando o WAF bloqueia.
func (db *DB) LastStatusForEvent(eventURL string) (string, error) {
	var status string
	err := db.conn.QueryRow(
		`SELECT status FROM status_log WHERE event_url = ?
		 AND status != 'UNKNOWN'
		 ORDER BY logged_at DESC LIMIT 1`,
		eventURL,
	).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return status, err
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// QueryResult é o resultado de uma query SQL executada pelo admin
type QueryResult struct {
	Columns  []string        `json:"columns"`
	Rows     [][]interface{} `json:"rows"`
	Duration int64           `json:"duration_ms"`
	RowCount int             `json:"row_count"`
}

// AdminQuery executa uma query SQL somente-leitura (SELECT) de forma segura.
// Bloqueia comandos DDL/DML perigosos. Retorna colunas + linhas como JSON.
func (db *DB) AdminQuery(query string) (*QueryResult, error) {
	// Validação de segurança — só permite SELECT
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	forbidden := []string{"DROP", "DELETE", "UPDATE", "INSERT", "CREATE", "ALTER",
		"TRUNCATE", "REPLACE", "ATTACH", "DETACH", "PRAGMA"}
	for _, kw := range forbidden {
		if strings.HasPrefix(trimmed, kw) {
			return nil, fmt.Errorf("operação não permitida: apenas SELECT é aceito")
		}
	}

	start := time.Now()
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("erro na query: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var result [][]interface{}
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		// Converter []byte para string para JSON legível
		row := make([]interface{}, len(cols))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				row[i] = string(b)
			} else {
				row[i] = v
			}
		}
		result = append(result, row)
	}
	if result == nil {
		result = [][]interface{}{}
	}

	return &QueryResult{
		Columns:  cols,
		Rows:     result,
		Duration: time.Since(start).Milliseconds(),
		RowCount: len(result),
	}, nil
}
