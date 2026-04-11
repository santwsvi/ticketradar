package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

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

		CREATE INDEX IF NOT EXISTS idx_status_log_url ON status_log(event_url);
		CREATE INDEX IF NOT EXISTS idx_status_log_logged_at ON status_log(logged_at);
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

func (db *DB) Close() error {
	return db.conn.Close()
}
