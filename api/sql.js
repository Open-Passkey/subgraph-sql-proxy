// Vercel Edge Function to proxy Coinbase SQL API requests with JWT authentication
// Set these environment variables in Vercel:
// - CDP_KEY_NAME: Your CDP API key name (from Portal)
// - CDP_PRIVATE_KEY: Your CDP private key (PEM format, with \n replaced by actual newlines)

export const config = {
  runtime: 'edge',
};

const COINBASE_SQL_API = 'https://api.cdp.coinbase.com/platform/v2/data/query/run';
const API_HOST = 'api.cdp.coinbase.com';

// Generate JWT for Coinbase API authentication
async function generateJWT(keyName, privateKeyPem) {
  const now = Math.floor(Date.now() / 1000);
  
  // JWT Header
  const header = {
    alg: 'ES256',
    kid: keyName,
    typ: 'JWT',
    nonce: crypto.randomUUID()
  };
  
  // JWT Payload per Coinbase docs
  const payload = {
    sub: keyName,
    iss: 'cdp',
    nbf: now,
    exp: now + 120,  // 2 minutes
    uri: `POST ${API_HOST}/platform/v2/data/query/run`
  };
  
  // Base64URL encode
  const base64url = (obj) => {
    const json = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(json);
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  
  const headerB64 = base64url(header);
  const payloadB64 = base64url(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  
  // Import private key and sign
  try {
    // Parse PEM format - handle both EC and PKCS8 formats
    let pemContents = privateKeyPem
      .replace('-----BEGIN EC PRIVATE KEY-----', '')
      .replace('-----END EC PRIVATE KEY-----', '')
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\\n/g, '')
      .replace(/\s/g, '');
    
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    
    const key = await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      new TextEncoder().encode(signingInput)
    );
    
    // Convert DER signature to raw R||S format for ES256
    const sigArray = new Uint8Array(signature);
    const sigB64 = btoa(String.fromCharCode(...sigArray))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    
    return `${signingInput}.${sigB64}`;
  } catch (e) {
    console.error('JWT signing error:', e);
    throw new Error(`JWT signing failed: ${e.message}`);
  }
}

export default async function handler(request) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

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
    // Get credentials from environment variables
    const keyName = process.env.CDP_KEY_NAME;
    const privateKey = process.env.CDP_PRIVATE_KEY;
    
    if (!keyName || !privateKey) {
      return new Response(JSON.stringify({ 
        error: 'Server not configured',
        hint: 'CDP_KEY_NAME and CDP_PRIVATE_KEY environment variables must be set in Vercel',
        setup: 'Go to Vercel → Settings → Environment Variables and add your CDP Secret API Key credentials'
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const body = await request.json();

    if (!body.sql) {
      return new Response(JSON.stringify({ error: 'Missing required field: sql' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Generate JWT
    let jwt;
    try {
      jwt = await generateJWT(keyName, privateKey);
    } catch (e) {
      return new Response(JSON.stringify({ 
        error: 'JWT generation failed', 
        details: e.message 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Forward to Coinbase SQL API
    const response = await fetch(COINBASE_SQL_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwt}`,
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
      const text = await response.text();
      return new Response(JSON.stringify({ 
        error: 'Coinbase API returned non-JSON response',
        status: response.status,
        preview: text.substring(0, 500)
      }), {
        status: response.status,
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
