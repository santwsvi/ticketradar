#!/bin/bash
# setup-cloudflare.sh — Configura DNS do TicketRadar via Cloudflare API
# Uso: bash setup-cloudflare.sh
#
# Pré-requisitos:
# 1. Domínio adicionado no Cloudflare (zona ativa)
# 2. CF_TOKEN — API Token com permissão Zone:DNS:Edit
# 3. CF_ZONE_ID — ID da zona (Cloudflare Dashboard → Overview → Zone ID)

set -e

# ── Credenciais ────────────────────────────────────────────────────────────────
CF_TOKEN="${CF_TOKEN:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
DOMAIN="ticketradar.com.br"
RAILWAY_TARGET="ticketradar-production-f6a4.up.railway.app"

if [ -z "$CF_TOKEN" ] || [ -z "$CF_ZONE_ID" ]; then
  echo "❌ Configure as variáveis:"
  echo "   export CF_TOKEN=seu_token_cloudflare"
  echo "   export CF_ZONE_ID=seu_zone_id"
  exit 1
fi

# ── Helper ─────────────────────────────────────────────────────────────────────
cf_api() {
  local method="$1" path="$2" data="$3"
  curl -s -X "$method" "https://api.cloudflare.com/client/v4/$path" \
    -H "Authorization: Bearer $CF_TOKEN" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"}
}

add_record() {
  local type="$1" name="$2" content="$3" proxied="${4:-false}" priority="${5:-}"
  local data="{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\",\"proxied\":$proxied,\"ttl\":1"
  [ -n "$priority" ] && data="${data},\"priority\":$priority"
  data="${data}}"

  result=$(cf_api POST "zones/$CF_ZONE_ID/dns_records" "$data")
  if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('success') else 1)" 2>/dev/null; then
    echo "✅ $type $name → $content"
  else
    echo "⚠️  $type $name → $content"
    echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print('   Erro:', d.get('errors',['?'])[0])" 2>/dev/null || true
  fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎟️  TicketRadar — Configuração DNS Cloudflare"
echo "   Domínio: $DOMAIN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Site (Railway) ──────────────────────────────────────────────────────────
echo "=== 1. Site (Railway) ==="
add_record "CNAME" "@"   "$RAILWAY_TARGET" "true"
add_record "CNAME" "www" "$DOMAIN"          "true"

echo ""

# ── 2. Email Routing (receber em privacidade@) ─────────────────────────────────
echo "=== 2. Email Routing (recebimento) ==="
add_record "MX" "@" "route1.mx.cloudflare.net" "false" "14"
add_record "MX" "@" "route2.mx.cloudflare.net" "false" "40"
add_record "MX" "@" "route3.mx.cloudflare.net" "false" "77"
add_record "TXT" "@" "v=spf1 include:_spf.mx.cloudflare.net ~all" "false"

echo ""

# ── 3. Configurar regra de roteamento para privacidade@ ───────────────────────
echo "=== 3. Email Routing Rule (privacidade@ → Gmail) ==="
RULE_DATA='{
  "actions": [{"type": "forward", "value": ["victorgsantosrocha@gmail.com"]}],
  "enabled": true,
  "matchers": [{"field": "to", "type": "literal", "value": "privacidade@'$DOMAIN'"}],
  "name": "privacidade@ → Gmail"
}'
result=$(cf_api POST "zones/$CF_ZONE_ID/email/routing/rules" "$RULE_DATA")
if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('success') else 1)" 2>/dev/null; then
  echo "✅ privacidade@$DOMAIN → victorgsantosrocha@gmail.com"
else
  echo "⚠️  Regra de routing — configure manualmente no dashboard"
  echo "   Cloudflare → Email → Email Routing → Create address"
  echo "   privacidade@$DOMAIN → victorgsantosrocha@gmail.com"
fi

echo ""

# ── 4. Resend DKIM/SPF (instruções) ───────────────────────────────────────────
echo "=== 4. Resend DKIM/SPF (instruções) ==="
echo ""
echo "   Execute após verificar o domínio no Resend:"
echo "   https://resend.com/domains → Add Domain → $DOMAIN"
echo ""
echo "   O Resend vai mostrar records como:"
echo "   TXT  resend._domainkey.$DOMAIN  → (valor DKIM gerado)"
echo "   TXT  $DOMAIN                   → v=spf1 include:amazonses.com ~all"
echo ""
echo "   Cole os valores e rode:"
echo "   bash setup-cloudflare.sh --resend DKIM_VALUE"

# ── 5. Configurar HTTPS redirect ───────────────────────────────────────────────
echo ""
echo "=== 5. HTTPS redirect ==="
REDIRECT_DATA='{
  "targets": [{"target": "url", "constraint": {"operator": "matches", "value": "http://*'$DOMAIN'/*"}}],
  "actions": [{"id": "forwarding_url", "value": {"url": "https://$1", "status_code": 301}}],
  "status": "active",
  "description": "HTTP → HTTPS redirect"
}'
# Isso é feito via Page Rules — configurar manualmente
echo "ℹ️  Configure HTTP→HTTPS no Cloudflare:"
echo "   SSL/TLS → Edge Certificates → Always Use HTTPS → ON"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Configuração base concluída!"
echo ""
echo "Próximos passos manuais:"
echo "  1. Resend: verificar domínio e adicionar DKIM records"
echo "  2. Cloudflare: confirmar Email Routing (gmail envia confirmação)"
echo "  3. Railway: adicionar custom domain ticketradar.com.br"
echo "  4. Railway: atualizar ALLOWED_ORIGIN e EMAIL_FROM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
