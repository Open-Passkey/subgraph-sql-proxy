// Vercel Edge Function to proxy Coinbase SQL API requests
export const config = {
  runtime: 'edge',
};

// Coinbase SQL API endpoint
const COINBASE_SQL_API = 'https://api.developer.coinbase.com/platform/v1/sql/query';

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

    // Try different API endpoints
    const endpoints = [
      'https://api.developer.coinbase.com/platform/v1/sql/query',
      'https://api.cdp.coinbase.com/platform/v2/data/query/run',
      'https://api.cdp.coinbase.com/data/sql/v1/query'
    ];

    let lastError = null;
    let lastResponse = null;

    for (const endpoint of endpoints) {
      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
          },
          body: JSON.stringify(body),
        });

        const contentType = response.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
          const data = await response.json();
          
          // If successful or got a meaningful error, return it
          if (response.ok || data.error) {
            return new Response(JSON.stringify({
              ...data,
              _debug: { endpoint, status: response.status }
            }), {
              status: response.ok ? 200 : response.status,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
          }
        } else {
          // Got HTML or other non-JSON response
          const text = await response.text();
          lastError = { endpoint, status: response.status, body: text.substring(0, 200) };
        }
      } catch (e) {
        lastError = { endpoint, error: e.message };
      }
    }

    // All endpoints failed
    return new Response(JSON.stringify({ 
      error: 'All API endpoints failed',
      lastError,
      hint: 'Client API Key may not work for SQL API. Try using Secret API Key from CDP Portal.'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message, stack: error.stack }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}
