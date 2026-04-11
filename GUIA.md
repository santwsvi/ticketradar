# TicketRadar — Guia Completo: Local → Prod → LGPD

## 1. TESTAR LOCALMENTE

### Pré-requisitos
```bash
# Verificar Go instalado
go version  # precisa ser >= 1.21

# Instalar Railway CLI (para deploy depois)
brew install railway
```

### Subir o servidor
```bash
cd ~/Documents/Pessoal/ticketradar

# Carrega as variáveis e sobe
export $(grep -v '^#' .env | xargs)
go run ./cmd/server
# → 🌐 Servidor rodando em http://localhost:8080
```

### Rodar a suite de testes
```bash
# Em outro terminal (servidor precisa estar rodando)
bash test-local.sh
```

### Testes manuais via curl
```bash
# 1. Health check
curl http://localhost:8080/health

# 2. Status dos eventos monitorados
curl http://localhost:8080/api/status | python3 -m json.tool

# 3. Cadastro na waitlist (LGPD compliant)
curl -X POST http://localhost:8080/api/waitlist \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Victor",
    "email": "victor@teste.com",
    "whatsapp": "+5531999999999",
    "categories": "shows internacionais",
    "consent_terms": true,
    "consent_marketing": true
  }'

# 4. Direito ao esquecimento — LGPD Art. 18, IV
curl -X DELETE "http://localhost:8080/api/waitlist?email=victor@teste.com"

# 5. Ver o banco SQLite diretamente
sqlite3 ticketradar.db "SELECT * FROM waitlist;"
sqlite3 ticketradar.db "SELECT * FROM lgpd_audit;"
```

---

## 2. SUBIR EM PRODUÇÃO (Railway)

### Passo 1 — Criar conta e projeto no Railway
```bash
# Login (abre browser)
railway login

# Criar novo projeto
railway init
# → Nome: ticketradar
# → Tipo: Empty project
```

### Passo 2 — Configurar variáveis de ambiente no Railway
```bash
# Configurar CADA variável (nunca commitar o .env!)
railway variables set PORT=8080
railway variables set CHECK_INTERVAL=30s
railway variables set DB_PATH=/data/ticketradar.db
railway variables set EMAIL_FROM=seu@gmail.com
railway variables set EMAIL_PASSWORD="$(openssl rand -hex 16)"
railway variables set EMAIL_TO=seu@gmail.com
railway variables set TWILIO_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
railway variables set TWILIO_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
railway variables set TWILIO_FROM=+1XXXXXXXXXX
railway variables set TWILIO_TO=+55XXXXXXXXXXX
```

### Passo 3 — Adicionar volume persistente para o banco
```
No dashboard Railway:
1. Clique no serviço → Settings → Volumes
2. Add Volume: mount path = /data
3. Isso garante que o SQLite não perde dados entre deploys
```

### Passo 4 — Deploy
```bash
# Primeiro deploy
railway up

# Ou conectar ao GitHub para auto-deploy em cada push
railway link
git push origin main  # → Railway deploya automaticamente
```

### Passo 5 — Domínio
```
No dashboard Railway:
Settings → Networking → Generate Domain
→ ticketradar.up.railway.app (grátis)

Para domínio próprio (ex: ticketradar.app):
Settings → Networking → Custom Domain → ticketradar.app
→ Adicionar CNAME no seu registrador (Registro.br)
```

### Passo 6 — Verificar em produção
```bash
# Health check
curl https://ticketradar.up.railway.app/health

# Status dos eventos
curl https://ticketradar.up.railway.app/api/status

# Ver logs em tempo real
railway logs
```

---

## 3. CONFORMIDADE LGPD — Checklist Completo

### Base legal (Art. 7, LGPD)
O TicketRadar usa **consentimento** como base legal (Art. 7, I).
O campo `consent_terms: true` é obrigatório no cadastro — o servidor rejeita sem ele.

### O que coletamos e por quê (princípio da minimização — Art. 6, III)

| Dado | Por quê coletamos | Onde fica | Retenção |
|------|-------------------|-----------|----------|
| Nome | Personalização de alertas | SQLite (local) | Até exclusão pelo usuário |
| E-mail | Canal de notificação | SQLite | Até exclusão |
| WhatsApp | Canal de notificação (opcional) | SQLite | Até exclusão |
| Categorias | Filtrar eventos relevantes | SQLite | Até exclusão |
| consent_at | Prova de consentimento | SQLite | 5 anos (obrigação legal) |

**NÃO coletamos:** CPF, endereço, dados de pagamento, localização, dados sensíveis.

### Direitos dos titulares implementados (Art. 18)

| Direito | Endpoint | Como funciona |
|---------|----------|---------------|
| Acesso (II) | `GET /api/me?email=x` | Retorna todos os dados do usuário |
| Portabilidade (V) | `GET /api/me?email=x&format=json` | Exporta em JSON |
| Exclusão (IV) | `DELETE /api/waitlist?email=x` | Remove tudo do banco |
| Revogação de consentimento (IX) | `DELETE /api/waitlist?email=x` | Idem |

### Audit log (Art. 37)
Toda operação sobre dados pessoais é registrada na tabela `lgpd_audit`:
- INSERT (cadastro)
- DELETE (exclusão)
- EXPORT (portabilidade)

O email **nunca é armazenado em claro** no audit — apenas um hash FNV de 8 chars (não-reversível).

### Política de Privacidade (obrigatória — Art. 9)
Criar arquivo `web/privacidade.html` com:
- Quais dados são coletados
- Finalidade do tratamento
- Base legal (consentimento)
- Tempo de retenção
- Direitos do titular + como exercê-los
- Contato do encarregado (DPO): privacy@ticketradar.app

### Segurança dos dados (Art. 46)

```bash
# 1. Banco nunca fica em diretório público
DB_PATH=/data/ticketradar.db  # volume privado no Railway

# 2. Variáveis de ambiente nunca no código
# ✅ Todas as credenciais via env vars (já implementado)

# 3. HTTPS obrigatório em produção
# ✅ Railway provisiona TLS automaticamente

# 4. Não logamos dados pessoais
# ✅ Logs mostram "victor@..." nunca o dado completo em produção
# Adicionar no main.go em produção:
# log.Printf("📧 Novo cadastro: %s (...) — total: %d", body.Name, count)
```

### Incidentes de segurança (Art. 48)
Se o banco vazar:
1. Notificar a ANPD em até 72h
2. Notificar os titulares afetados
3. Os dados expostos são: nome, e-mail, whatsapp, categorias de interesse
4. **Não há dados financeiros, senhas ou CPF**

---

## 4. GIT — O QUE NUNCA COMMITAR

```bash
# .gitignore já configurado — verificar:
cat .gitignore

# Deve conter:
# .env          ← credenciais
# *.db          ← banco com dados pessoais
# bin/          ← binários compilados

# Verificar se .env está ignorado antes de fazer push:
git status  # .env NÃO deve aparecer aqui
```

### Se acidentalmente commitar credenciais:
```bash
# Rotacionar imediatamente:
# 1. Gmail: gerar nova App Password em myaccount.google.com/apppasswords
# 2. Twilio: regenerar Auth Token no console.twilio.com
# 3. Limpar o histórico do git:
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch .env' HEAD
git push --force
```

---

## 5. RESUMO DOS COMANDOS DO DIA A DIA

```bash
# Subir local
export $(grep -v '^#' .env | xargs) && go run ./cmd/server

# Testar
bash test-local.sh

# Deploy prod
git add . && git commit -m "feat: ..." && git push
# → Railway deploya automaticamente

# Ver logs prod
railway logs --tail

# Ver status dos eventos em prod
curl https://ticketradar.up.railway.app/api/status

# Backup do banco (antes de qualquer mudança grande)
railway run sqlite3 /data/ticketradar.db .dump > backup-$(date +%Y%m%d).sql
```
