/**
 * TicketRadar — SMS Outreach Worker
 *
 * Cron job que roda a cada hora e envia SMS de boas-vindas
 * para novos cadastros que ainda não foram contactados.
 *
 * Fluxo:
 *   1. Chama GET /admin/sms/pending?type=welcome no backend
 *   2. Backend busca pendentes, envia via Twilio e registra no banco
 *   3. Worker registra o resultado para auditoria no KV
 *
 * Cron schedule: a cada hora (0 * * * *)
 */

export default {
  // Handler HTTP (para testes manuais)
  async fetch(request, env) {
    const url = new URL(request.url)

    // Verificar auth
    const token = request.headers.get('X-Worker-Token')
    if (!token || token !== env.WORKER_TOKEN) {
      return new Response(JSON.stringify({ error: 'unauthorized' }), {
        status: 401, headers: { 'Content-Type': 'application/json' }
      })
    }

    if (url.pathname === '/run-outreach') {
      return await runOutreach(env, url.searchParams.get('dry_run') === 'true')
    }

    if (url.pathname === '/stats') {
      return await getStats(env)
    }

    return new Response(JSON.stringify({
      routes: ['/run-outreach', '/run-outreach?dry_run=true', '/stats']
    }), { headers: { 'Content-Type': 'application/json' } })
  },

  // Cron trigger — executa a cada hora
  async scheduled(event, env, ctx) {
    console.log(`[Cron] Rodando outreach às ${new Date().toISOString()}`)
    ctx.waitUntil(runOutreach(env, false))
  }
}

async function runOutreach(env, dryRun = false) {
  const baseURL = env.BACKEND_URL || 'https://ticketradar.com.br'
  const adminUser = env.ADMIN_USER || 'admin'
  const adminPass = env.ADMIN_PASS

  if (!adminPass) {
    return jsonResponse({ error: 'ADMIN_PASS não configurado' }, 500)
  }

  const basicAuth = btoa(`${adminUser}:${adminPass}`)
  const endpoint = `${baseURL}/admin/sms/pending?type=welcome${dryRun ? '&dry_run=true' : ''}`

  console.log(`[Outreach] Chamando ${endpoint}`)

  let response
  try {
    response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/json',
      },
      cf: { cacheEverything: false }
    })
  } catch (err) {
    console.error(`[Outreach] Erro ao chamar backend: ${err.message}`)
    return jsonResponse({ error: err.message }, 500)
  }

  if (!response.ok) {
    const body = await response.text()
    console.error(`[Outreach] Backend retornou ${response.status}: ${body}`)
    return jsonResponse({ error: `Backend HTTP ${response.status}`, body }, 500)
  }

  const result = await response.json()

  // Salvar log no KV para auditoria
  if (env.OUTREACH_KV) {
    const logKey = `run:${new Date().toISOString().slice(0, 16)}`
    await env.OUTREACH_KV.put(logKey, JSON.stringify({
      timestamp: new Date().toISOString(),
      dry_run: dryRun,
      ...result
    }), { expirationTtl: 60 * 60 * 24 * 30 }) // 30 dias
  }

  console.log(`[Outreach] Resultado: ${result.sent} enviados, ${result.failed} falhas de ${result.processed} pendentes`)

  return jsonResponse({
    ok: true,
    dry_run: dryRun,
    timestamp: new Date().toISOString(),
    ...result
  })
}

async function getStats(env) {
  const baseURL = env.BACKEND_URL || 'https://ticketradar.com.br'
  const adminUser = env.ADMIN_USER || 'admin'
  const adminPass = env.ADMIN_PASS
  const basicAuth = btoa(`${adminUser}:${adminPass}`)

  const response = await fetch(`${baseURL}/admin/sms/stats`, {
    headers: { 'Authorization': `Basic ${basicAuth}` }
  })
  const stats = await response.json()

  // Últimos runs do KV
  let recentRuns = []
  if (env.OUTREACH_KV) {
    const list = await env.OUTREACH_KV.list({ prefix: 'run:' })
    for (const key of list.keys.slice(-5)) {
      const val = await env.OUTREACH_KV.get(key.name)
      if (val) recentRuns.push(JSON.parse(val))
    }
  }

  return jsonResponse({ stats, recent_runs: recentRuns.reverse() })
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}
