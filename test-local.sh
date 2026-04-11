#!/bin/bash
# test-local.sh — Testa todas as funcionalidades localmente
# Uso: bash test-local.sh

set -e

BASE="http://localhost:8080"
PASS=0
FAIL=0

check() {
  local desc="$1"
  local result="$2"
  local expected="$3"
  if echo "$result" | grep -q "$expected"; then
    echo "✅ $desc"
    PASS=$((PASS+1))
  else
    echo "❌ $desc"
    echo "   esperado: $expected"
    echo "   recebido: $result"
    FAIL=$((FAIL+1))
  fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 TicketRadar — Test Suite Local"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Servidor respondendo
result=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/")
check "GET / retorna 200" "$result" "200"

# 2. API de status
result=$(curl -s "$BASE/api/status")
check "GET /api/status retorna JSON" "$result" "SOLD_OUT\|IN_SALE\|UNKNOWN"

# 3. Cadastro na waitlist — happy path
result=$(curl -s -X POST "$BASE/api/waitlist" \
  -H "Content-Type: application/json" \
  -d '{"name":"Teste","email":"teste@ticketradar.app","whatsapp":"+5511999999999","categories":"shows","consent_terms":true,"consent_marketing":true}')
check "POST /api/waitlist cadastra usuário" "$result" '"ok":true'

# 4. Email duplicado — deve aceitar silenciosamente (INSERT OR IGNORE)
result=$(curl -s -X POST "$BASE/api/waitlist" \
  -H "Content-Type: application/json" \
  -d '{"name":"Teste","email":"teste@ticketradar.app","consent_terms":true}')
check "POST /api/waitlist email duplicado não retorna erro" "$result" '"ok":true'

# 5. Email ausente — deve retornar erro
result=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/waitlist" \
  -H "Content-Type: application/json" \
  -d '{"name":"Sem email"}')
check "POST /api/waitlist sem email retorna 400" "$result" "400"

# 6. Método errado na waitlist
result=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/waitlist")
check "GET /api/waitlist retorna 405" "$result" "405"

# 7. LGPD — endpoint de exclusão sem token deve retornar 401
result=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/api/waitlist?email=teste@ticketradar.app")
check "DELETE /api/waitlist sem token retorna 401" "$result" "401"

# 8. LGPD — endpoint de exclusão com token correto deve retornar 200
result=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "X-Delete-Token: ${DELETE_TOKEN}" \
  "$BASE/api/waitlist?email=teste@ticketradar.app")
check "DELETE /api/waitlist com token retorna 200" "$result" "200"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Resultado: ✅ $PASS passou | ❌ $FAIL falhou"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
