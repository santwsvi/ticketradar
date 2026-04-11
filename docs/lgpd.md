# TicketRadar — Conformidade LGPD

## Resumo Executivo

| Item | Status |
|------|--------|
| Base legal definida | ✅ Consentimento (Art. 7, I) |
| Minimização de dados | ✅ Apenas o necessário coletado |
| Registro de consentimento | ✅ Timestamp + flags no banco |
| Direito ao esquecimento | ✅ DELETE /api/waitlist |
| Portabilidade | ✅ GET /api/me |
| Audit log | ✅ Tabela lgpd_audit (hashes) |
| Segurança técnica | ✅ TLS, WAL, SHA-256, rate limit |
| Política de Privacidade | ✅ /privacidade.html |
| Termos de Uso | ✅ /termos.html |
| DPO designado | ⚠️ Pendente formalização |

## Dados Coletados

| Dado | Finalidade | Base Legal | Retenção |
|------|-----------|-----------|---------|
| Nome | Personalização | Consentimento (Art. 7, I) | Até exclusão |
| E-mail | Notificações | Consentimento | Até exclusão |
| WhatsApp | Notificações (opcional) | Consentimento | Até exclusão |
| Categorias | Filtrar alertas relevantes | Consentimento | Até exclusão |
| consent_at | Prova de consentimento | Obrigação legal (Art. 8) | 5 anos |

**NÃO coletamos:** CPF, RG, endereço, dados financeiros, localização, dados de saúde, dados sensíveis (Art. 11).

## Direitos dos Titulares (Art. 18)

### I — Confirmação de tratamento
Resposta: "Sim, tratamos seus dados para enviar alertas de ingressos."

### II — Acesso aos dados
Endpoint: `GET /api/me?email=X&token=TOKEN`

### IV — Eliminação (Direito ao Esquecimento)
Endpoint: `DELETE /api/waitlist?email=X` (requer X-Delete-Token)

### V — Portabilidade
Endpoint: `GET /api/me?email=X&token=TOKEN` (retorna JSON com todos os dados)

### IX — Revogação de consentimento
Mesmo endpoint do IV — ao deletar, o consentimento é revogado.

### Como exercer os direitos
Contato: privacidade@ticketradar.app

## Audit Log

Toda operação sobre dados pessoais é registrada na tabela `lgpd_audit`:

```sql
-- Exemplo de entrada
action: 'DELETE'
email_hash: 'a3f2b1c4...'  -- SHA-256(salt + email), não reversível
logged_at: '2026-04-11 20:00:00'
```

O email **nunca é armazenado em claro** no audit. Usamos SHA-256 com salt fixo (`ticketradar-lgpd-audit-v1`) — resistente a rainbow table.

## Segurança Técnica (Art. 46)

- **TLS/HTTPS**: provisionado pelo Railway em produção
- **SQLite WAL**: sem corrupção por concorrência
- **Sem credenciais no código**: 100% via variáveis de ambiente
- **Logs sem PII**: emails mascarados (`vic***@dominio.com`)
- **Rate limiting**: 3 req/min por IP no cadastro
- **Security headers**: CSP, X-Frame-Options, XCTO, Referrer-Policy
- **CORS configurável**: restrito ao domínio do produto em produção

## Incidentes de Segurança (Art. 48)

Em caso de vazamento:
1. Notificar ANPD em até **72 horas** via sei.anpd.gov.br
2. Notificar titulares afetados por e-mail
3. Dados expostos: nome, e-mail, whatsapp, categorias
4. **Não há dados financeiros, senhas ou CPF**

## DPO (Encarregado de Dados)

| Item | Informação |
|------|-----------|
| Nome | Victor Gabriel Santos Rocha |
| E-mail | privacidade@ticketradar.app |
| Formalização | Pendente publicação no site |

## Referências Legais

- [Lei 13.709/2018 — LGPD](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [ANPD — Autoridade Nacional de Proteção de Dados](https://www.gov.br/anpd)
- [Guia ANPD — Bases Legais](https://www.gov.br/anpd/pt-br/documentos-e-publicacoes/guia-bases-legais)
