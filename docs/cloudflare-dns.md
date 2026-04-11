# TicketRadar — Guia de DNS e Cloudflare

## Visão Geral

```
ticketradar.com.br
├── @ (apex)         → CNAME ticketradar-production-f6a4.up.railway.app  (site)
├── www              → CNAME ticketradar-production-f6a4.up.railway.app  (www → apex)
├── noreply          → Resend SPF/DKIM (envio de email)
└── privacidade      → Email routing → victorgsantosrocha@gmail.com
```

---

## Passo 1 — Registrar domínio no Registro.br

1. Acesse: https://registro.br/registro/dominio/novo/
2. Busque: `ticketradar.com.br`
3. Preencha com CPF e dados pessoais
4. Na etapa de DNS, escolha **"Servidores DNS externos"**
5. Adicione os nameservers do Cloudflare (você pega no Passo 2)
6. Confirme e pague (~R$ 40/ano)

---

## Passo 2 — Criar zona no Cloudflare

1. Acesse: https://dash.cloudflare.com
2. Clique em **"Add a site"**
3. Digite: `ticketradar.com.br`
4. Escolha o plano **Free**
5. Cloudflare vai detectar os DNS atuais e mostrar os **nameservers**
   - Exemplo: `xxx.ns.cloudflare.com` e `yyy.ns.cloudflare.com`
6. Copie esses nameservers e cole no Registro.br (Passo 1, etapa 5)
7. Aguarde propagação (pode levar de minutos a 24h)

---

## Passo 3 — Configurar DNS no Cloudflare

Após a zona estar ativa, adicione os seguintes records:

### Site (Railway)

| Tipo  | Nome | Conteúdo | Proxy | TTL |
|-------|------|----------|-------|-----|
| CNAME | @    | ticketradar-production-f6a4.up.railway.app | ✅ Proxied | Auto |
| CNAME | www  | ticketradar.com.br | ✅ Proxied | Auto |

> **Nota:** Cloudflare transforma CNAME no apex (@) em ALIAS/ANAME automaticamente (CNAME Flattening). Railway aceita.

### Email — Resend (envio de noreply@ticketradar.com.br)

Os records abaixo são gerados pelo Resend ao verificar o domínio.
Acesse https://resend.com/domains → Add Domain → `ticketradar.com.br`
O Resend vai gerar os valores exatos para:

| Tipo  | Nome | Conteúdo |
|-------|------|----------|
| TXT   | resend._domainkey.ticketradar.com.br | (valor gerado pelo Resend) |
| TXT   | ticketradar.com.br | v=spf1 include:amazonses.com ~all |

### Email — Routing (receber em privacidade@ticketradar.com.br)

Cloudflare Email Routing redireciona emails recebidos para o Gmail.

| Tipo  | Nome | Conteúdo | Prioridade |
|-------|------|----------|------------|
| MX    | @    | route1.mx.cloudflare.net | 14 |
| MX    | @    | route2.mx.cloudflare.net | 40 |
| MX    | @    | route3.mx.cloudflare.net | 77 |
| TXT   | @    | v=spf1 include:_spf.mx.cloudflare.net ~all | - |

> Os records MX são adicionados automaticamente quando você ativa Email Routing no Cloudflare.

---

## Passo 4 — Configurar Railway para o domínio

```bash
# Adicionar domínio customizado no Railway
railway domain --service ticketradar.com.br

# Ou via dashboard:
# Railway → serviço → Settings → Networking → Custom Domain
# Adicionar: ticketradar.com.br e www.ticketradar.com.br
```

Após adicionar, Railway gera um CNAME target.
Atualizar o CNAME no Cloudflare com o valor correto.

---

## Passo 5 — Configurar Resend para noreply@ticketradar.com.br

1. Acesse: https://resend.com/domains
2. Clique em **"Add Domain"**
3. Digite: `ticketradar.com.br`
4. Resend gera os DNS records necessários (DKIM + SPF)
5. Adicione esses records no Cloudflare (Passo 3)
6. Clique em "Verify" no Resend
7. Atualizar variável no Railway:
   ```bash
   railway variables set EMAIL_FROM=noreply@ticketradar.com.br
   ```

---

## Passo 6 — Configurar Cloudflare Email Routing

1. Cloudflare Dashboard → seu domínio → **Email** → **Email Routing**
2. Ativar Email Routing
3. Cloudflare adiciona os records MX automaticamente
4. Em **Routing Rules** → **Create address**:
   - Address: `privacidade@ticketradar.com.br`
   - Action: **Send to** → `victorgsantosrocha@gmail.com`
5. Confirmar no Gmail (Cloudflare envia um email de confirmação)

---

## Passo 7 — Atualizar variáveis no Railway

```bash
railway variables set \
  ALLOWED_ORIGIN="https://ticketradar.com.br" \
  EMAIL_FROM="noreply@ticketradar.com.br"
```

---

## Checklist final

```
[ ] Domínio registrado no Registro.br
[ ] Zona criada no Cloudflare (Free)
[ ] Nameservers do Cloudflare configurados no Registro.br
[ ] CNAME @ → Railway (proxied)
[ ] CNAME www → ticketradar.com.br (proxied)
[ ] Domínio verificado no Resend (DKIM + SPF)
[ ] Email Routing ativado no Cloudflare
[ ] privacidade@ → victorgsantosrocha@gmail.com
[ ] Custom domain no Railway: ticketradar.com.br
[ ] EMAIL_FROM=noreply@ticketradar.com.br no Railway
[ ] ALLOWED_ORIGIN=https://ticketradar.com.br no Railway
[ ] HTTPS automático (Cloudflare + Railway provisionam TLS)
[ ] Testar envio de email via noreply@
[ ] Testar recebimento em privacidade@
```
