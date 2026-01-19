// Vercel Edge Function to proxy Coinbase SQL API requests
export const config = {
  runtime: 'edge',
};

// Coinbase SQL API endpoint (from official docs)
const COINBASE_SQL_API = 'https://api.cdp.coinbase.com/platform/v2/data/query/run';

export default async function handler(request) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key',
  };

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await request.json();
    const authHeader = request.headers.get('Authorization');
    const apiKey = request.headers.get('X-Api-Key') || (authHeader ? authHeader.replace('Bearer ', '') : null);

    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'API Key required (Authorization header or X-Api-Key)' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Validate request has sql field
    if (!body.sql) {
      return new Response(JSON.stringify({ error: 'Missing required field: sql' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Forward to Coinbase SQL API
    const response = await fetch(COINBASE_SQL_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        sql: body.sql,
        cache: body.cache || { maxAgeMs: 5000 }
      }),
    });

    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('application/json')) {
      const data = await response.json();
      return new Response(JSON.stringify(data), {
        status: response.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    } else {
      // Got non-JSON response (likely HTML error page)
      const text = await response.text();
      return new Response(JSON.stringify({ 
        error: 'Coinbase API returned non-JSON response',
        status: response.status,
        hint: 'Check if your CDP Client API Key is valid',
        preview: text.substring(0, 500)
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}
