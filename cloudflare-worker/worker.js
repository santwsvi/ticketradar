/**
 * TicketRadar — Cloudflare Worker Proxy
 * 
 * Atua como proxy para requests do monitor Go em direção à Ticketmaster.
 * O IP do Cloudflare (edge network) é diferente do IP do Railway — 
 * evita bloqueio por ASN/range de cloud providers.
 * 
 * Uso: GET /check?url=https://www.ticketmaster.com.br/event/...
 * Retorno: JSON com { salesStatus, httpStatus, blocked }
 * 
 * Autenticação: header X-Worker-Token (configurado como secret no Worker)
 */

export default {
  async fetch(request, env) {
    // Apenas GET permitido
    if (request.method !== 'GET') {
      return new Response(JSON.stringify({ error: 'method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Verificar token de autenticação
    const token = request.headers.get('X-Worker-Token')
    if (!token || token !== env.WORKER_TOKEN) {
      return new Response(JSON.stringify({ error: 'unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Extrair URL alvo
    const url = new URL(request.url)
    const targetURL = url.searchParams.get('url')
    if (!targetURL) {
      return new Response(JSON.stringify({ error: 'url param required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Validar que é um domínio permitido (SSRF protection)
    const allowedDomains = [
      'ticketmaster.com.br',
      'eventim.com.br',
      'sympla.com.br',
      'ingresso.com',
    ]
    let targetHost
    try {
      targetHost = new URL(targetURL).hostname.toLowerCase()
    } catch {
      return new Response(JSON.stringify({ error: 'invalid url' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }
    
    const allowed = allowedDomains.some(d => targetHost === d || targetHost.endsWith('.' + d))
    if (!allowed) {
      return new Response(JSON.stringify({ error: 'domain not allowed' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Fazer o request para a Ticketmaster com headers de browser real
    let resp
    try {
      resp = await fetch(targetURL, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
          'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Cache-Control': 'no-cache',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Upgrade-Insecure-Requests': '1',
        },
        cf: {
          // Cloudflare: não cachear este request
          cacheEverything: false,
          cacheTtl: 0,
        }
      })
    } catch (err) {
      return new Response(JSON.stringify({
        error: 'fetch failed',
        message: err.message,
        salesStatus: null,
        httpStatus: 0,
        blocked: true
      }), {
        status: 200, // retornar 200 para o Go não tratar como erro de rede
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Se bloqueado pelo WAF
    if (resp.status === 403 || resp.status === 429) {
      return new Response(JSON.stringify({
        salesStatus: null,
        httpStatus: resp.status,
        blocked: true
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Extrair salesStatus do HTML
    const body = await resp.text()
    const match = body.match(/"salesStatus"\s*:\s*"([^"]+)"/)
    const salesStatus = match ? match[1] : null

    return new Response(JSON.stringify({
      salesStatus,
      httpStatus: resp.status,
      blocked: false
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    })
  }
}
