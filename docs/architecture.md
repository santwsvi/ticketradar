# TicketRadar — Arquitetura

## Visão Geral

```
┌─────────────────────────────────────────────────────────────────┐
│                         USUÁRIO                                  │
│           Browser / SMS / Email / WhatsApp                       │
└────────────────────┬────────────────────────────────────────────┘
                     │ HTTPS
┌────────────────────▼────────────────────────────────────────────┐
│                    RAILWAY (prod)                                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Go HTTP Server (:8080)                 │    │
│  │                                                          │    │
│  │  Middlewares (em ordem):                                 │    │
│  │  requestID → securityHeaders → CORS → handler           │    │
│  │                                                          │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │    │
│  │  │ /        │  │ /api/*   │  │ /health              │  │    │
│  │  │ static   │  │ handlers │  │ /api/metrics         │  │    │
│  │  │ files    │  │          │  │ /api/history         │  │    │
│  │  └──────────┘  └────┬─────┘  └──────────────────────┘  │    │
│  │                     │                                    │    │
│  │  ┌──────────────────▼──────────────────────────────┐   │    │
│  │  │              Scheduler (goroutine)               │   │    │
│  │  │                                                  │   │    │
│  │  │  tick a cada 30s → checkAll() → goroutine/event │   │    │
│  │  │  tick a cada 1h  → PurgeOldStatusLogs()         │   │    │
│  │  └──────┬───────────────────────┬──────────────────┘   │    │
│  │         │                       │                        │    │
│  │  ┌──────▼──────┐       ┌────────▼────────┐             │    │
│  │  │   monitor   │       │     notify      │             │    │
│  │  │             │       │                 │             │    │
│  │  │ HTTP GET    │       │ SMS (Twilio)    │             │    │
│  │  │ salesStatus │       │ Email (Gmail)   │             │    │
│  │  │ extraction  │       │ (paralelo)      │             │    │
│  │  └──────┬──────┘       └─────────────────┘             │    │
│  │         │                                               │    │
│  │  ┌──────▼──────────────────────────────────────────┐   │    │
│  │  │              store (SQLite WAL)                  │   │    │
│  │  │                                                  │   │    │
│  │  │  waitlist     — dados de cadastro (LGPD)         │   │    │
│  │  │  status_log   — histórico de verificações (48h)  │   │    │
│  │  │  lgpd_audit   — audit log (SHA-256+salt)         │   │    │
│  │  └──────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Volume persistente: /data/ticketradar.db                        │
└─────────────────────────────────────────────────────────────────┘
```

## Fluxo de Monitoramento

```
Scheduler tick (30s)
     │
     ├─► goroutine: checkOne(BTS 28/10)
     │        │
     │        ├─ HTTP GET ticketmaster.com.br/event/...
     │        ├─ extractStatus() → salesStatus do JSON
     │        ├─ db.LogStatus(url, label, status)
     │        │
     │        └─ se status mudou para IN_SALE/ON_SALE:
     │               ├─ notify.SendAll() [paralelo]
     │               │     ├─ goroutine: SendSMS() → Twilio API
     │               │     └─ goroutine: SendEmail() → Gmail SMTP
     │               └─ log.Printf("🚨 DISPONÍVEL!")
     │
     ├─► goroutine: checkOne(BTS 30/10)
     └─► goroutine: checkOne(BTS 31/10)
```

## Fluxo de Cadastro (LGPD)

```
POST /api/waitlist
     │
     ├─ Rate limit: 3 req/min por IP
     ├─ Validação: email obrigatório
     ├─ Validação: consent_terms = true (LGPD Art. 7, I)
     │
     ├─ db.AddToWaitlist()
     │     ├─ INSERT OR IGNORE INTO waitlist (...)
     │     └─ db.auditLog("INSERT", SHA256(salt+email))
     │
     └─ Response: {"ok": true, "total": N}


DELETE /api/waitlist?email=x   (Header: X-Delete-Token)
     │
     ├─ Validação token (C3)
     ├─ db.auditLog("DELETE", SHA256(salt+email))  ← antes de deletar
     ├─ DELETE FROM waitlist WHERE email = ?
     └─ Response: {"ok": true}
```

## Banco de Dados

### Tabela: waitlist
| Coluna | Tipo | Descrição |
|--------|------|-----------|
| id | INTEGER PK | Auto-incremento |
| name | TEXT | Nome do usuário |
| email | TEXT UNIQUE | E-mail (dado pessoal) |
| whatsapp | TEXT NULL | WhatsApp opcional |
| categories | TEXT | Categorias de interesse |
| consent_marketing | INTEGER | 0/1 — consentimento marketing |
| consent_terms | INTEGER | 0/1 — aceite dos termos |
| consent_at | DATETIME | Timestamp do consentimento |
| created_at | DATETIME | Timestamp do cadastro |

### Tabela: status_log (TTL: 48h)
| Coluna | Tipo | Descrição |
|--------|------|-----------|
| id | INTEGER PK | Auto-incremento |
| event_url | TEXT | URL do evento |
| event_label | TEXT | Label legível (ex: "BTS 28/10") |
| status | TEXT | SOLD_OUT / IN_SALE / etc |
| logged_at | DATETIME | Timestamp da verificação |

### Tabela: lgpd_audit
| Coluna | Tipo | Descrição |
|--------|------|-----------|
| id | INTEGER PK | Auto-incremento |
| action | TEXT | INSERT / DELETE / EXPORT |
| email_hash | TEXT | SHA-256(salt + email) — não reversível |
| ip_hash | TEXT | Hash do IP (quando disponível) |
| logged_at | DATETIME | Timestamp da operação |

## Security Headers (toda resposta)

| Header | Valor | Proteção |
|--------|-------|---------|
| X-Content-Type-Options | nosniff | MIME sniffing |
| X-Frame-Options | DENY | Clickjacking |
| Referrer-Policy | strict-origin-when-cross-origin | Vazamento de URL |
| Content-Security-Policy | default-src 'self' + allowlist | XSS |

## Decisões de Design

### Por que SQLite?
- MVP: zero infra adicional, dados persistem em volume Railway
- WAL mode: suporta leituras concorrentes sem lock
- Quando escalar: migrar para Postgres é simples (mesma interface `database/sql`)

### Por que Go?
- Concorrência nativa (goroutines) para checar múltiplos eventos em paralelo
- Binário estático: Docker image < 15MB
- Performance: handles 10k+ req/s com recursos mínimos

### Por que SQLite e não Redis para rate limiting?
- Redis seria overkill para o volume atual do MVP
- O rate limiter in-memory (map + mutex) é suficiente para instância única
- Limitação: não funciona com múltiplas réplicas — aceitável no MVP

### Por que não JWT para autenticação?
- MVP usa token estático (DELETE_TOKEN) — simples e suficiente
- Quando houver login de usuário: migrar para JWT com refresh tokens
