# TicketRadar 🎟️

> Seja avisado por SMS, e-mail ou WhatsApp assim que ingressos ficarem disponíveis — antes de qualquer um.

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![LGPD Compliant](https://img.shields.io/badge/LGPD-Compliant-green)](docs/lgpd.md)

## O que é

TicketRadar é uma plataforma de alertas de disponibilidade de ingressos. Monitora páginas de eventos a cada 30 segundos e notifica via **SMS**, **e-mail** e **WhatsApp** quando detecta disponibilidade — ingressos residuais, lotes novos, cancelamentos.

100% legal: monitora apenas dados públicos. Não compra ingressos, não acessa contas, não viola ToS.

## Funcionalidades

- 🔍 Monitoramento de múltiplos eventos em paralelo
- 📱 Alertas multicanal: SMS (Twilio) + Email (Gmail)
- 🌐 Landing page com lista de espera
- 📊 Dashboard de monitoramento em tempo real
- 📖 API documentada (OpenAPI 3.0 / Swagger)
- 🔒 LGPD compliant (consentimento, portabilidade, exclusão, audit log)
- 🛡️ Rate limiting, security headers, CORS configurável

## Stack

| Camada | Tecnologia |
|--------|-----------|
| Backend | Go 1.26 |
| Banco | SQLite (WAL mode) |
| SMS | Twilio |
| Email | Gmail SMTP |
| Deploy | Railway + Docker |
| Frontend | HTML/CSS/JS (sem framework) |

## Desenvolvimento local

### Pré-requisitos

```bash
go version  # >= 1.21
```

### Setup

```bash
git clone https://github.com/victorgsrocha/ticketradar
cd ticketradar

# Configurar variáveis
cp .env.example .env
# Editar .env com suas credenciais

# Subir
export $(grep -v '^#' .env | xargs)
go run ./cmd/server
```

Acesse:
- `http://localhost:8080` — Landing page
- `http://localhost:8080/dashboard.html` — Dashboard
- `http://localhost:8080/docs.html` — API Docs

### Testes

```bash
# Servidor precisa estar rodando
bash test-local.sh
```

## Deploy (Railway)

Ver [GUIA.md](GUIA.md) para instruções completas de deploy.

```bash
railway login
railway init
railway variables set PORT=8080 DELETE_TOKEN=$(openssl rand -hex 32) ...
railway up
```

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|----------|------------|-----------|
| `PORT` | Não (default: 8080) | Porta do servidor |
| `DB_PATH` | Não (default: ./ticketradar.db) | Caminho do banco SQLite |
| `CHECK_INTERVAL` | Não (default: 30s) | Intervalo entre verificações |
| `ALLOWED_ORIGIN` | **Prod** | Origem permitida para CORS |
| `DELETE_TOKEN` | **Prod** | Token para DELETE /api/waitlist |
| `EMAIL_FROM` | Sim | Remetente Gmail |
| `EMAIL_PASSWORD` | Sim | Gmail App Password |
| `EMAIL_TO` | Sim | Destinatário dos alertas |
| `TWILIO_SID` | Sim | Twilio Account SID |
| `TWILIO_TOKEN` | Sim | Twilio Auth Token |
| `TWILIO_FROM` | Sim | Número Twilio |
| `TWILIO_TO` | Sim | Número de destino dos SMS |

## API

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/health` | GET | Health check |
| `/api/status` | GET | Status dos eventos monitorados |
| `/api/metrics` | GET | Métricas: uptime, checks, waitlist |
| `/api/history` | GET | Histórico de status (últimas 48h) |
| `/api/waitlist` | POST | Cadastro na lista de espera |
| `/api/waitlist` | DELETE | Exclusão de dados (LGPD Art. 18, IV) |
| `/api/me` | GET | Portabilidade de dados (LGPD Art. 18, V) |

Documentação completa: `/docs.html`

## LGPD

Ver [docs/lgpd.md](docs/lgpd.md) para detalhes completos de conformidade.

**Resumo:**
- Base legal: consentimento (Art. 7, I)
- Dados coletados: nome, e-mail, WhatsApp (opcional), categorias de interesse
- Não coletamos: CPF, dados financeiros, localização, dados sensíveis
- Direito ao esquecimento: `DELETE /api/waitlist?email=x`
- Portabilidade: `GET /api/me?email=x&token=TOKEN`
- Contato DPO: privacidade@ticketradar.app

## Segurança

Ver [SECURITY.md](SECURITY.md) para reportar vulnerabilidades.

## Licença

[MIT](LICENSE) © 2026 Victor Gabriel Santos Rocha
