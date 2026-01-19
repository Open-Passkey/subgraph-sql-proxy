// Vercel Edge Function to proxy Coinbase SQL API requests with JWT authentication
// Set these environment variables in Vercel:
// - CDP_KEY_NAME: Your CDP API key ID (e.g., "06e27a55-d5f5-4e93-9e16-b33be1493380")
// - CDP_PRIVATE_KEY: Your CDP private key (base64 string from downloaded JSON)

export const config = {
  runtime: 'edge',
};

const COINBASE_SQL_API = 'https://api.cdp.coinbase.com/platform/v2/data/query/run';
const API_HOST = 'api.cdp.coinbase.com';

// Base64URL encode helper
function base64url(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  } else if (typeof data === 'object' && !(data instanceof Uint8Array)) {
    data = new TextEncoder().encode(JSON.stringify(data));
  }
  const base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Generate JWT for Coinbase API authentication using Ed25519
async function generateJWT(keyId, privateKeyBase64) {
  const now = Math.floor(Date.now() / 1000);
  
  // JWT Header for Ed25519
  const header = {
    alg: 'EdDSA',
    kid: keyId,
    typ: 'JWT',
    nonce: crypto.randomUUID()
  };
  
  // JWT Payload per Coinbase docs
  const payload = {
    sub: keyId,
    iss: 'cdp',
    nbf: now,
    exp: now + 120,  // 2 minutes
    uri: `POST ${API_HOST}/platform/v2/data/query/run`
  };
  
  const headerB64 = base64url(header);
  const payloadB64 = base64url(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  
  try {
    // Decode the base64 private key
    // CDP Ed25519 keys are 64 bytes: 32-byte seed + 32-byte public key
    const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
    
    // Extract the 32-byte seed (first half)
    const seed = keyBytes.slice(0, 32);
    
    // Import as Ed25519 private key using PKCS8 format
    // We need to wrap the seed in PKCS8 format for Web Crypto
    const pkcs8Prefix = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    ]);
    const pkcs8Key = new Uint8Array(pkcs8Prefix.length + seed.length);
    pkcs8Key.set(pkcs8Prefix);
    pkcs8Key.set(seed, pkcs8Prefix.length);
    
    const key = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8Key,
      { name: 'Ed25519' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign(
      'Ed25519',
      key,
      new TextEncoder().encode(signingInput)
    );
    
    const sigB64 = base64url(new Uint8Array(signature));
    
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
    const keyId = process.env.CDP_KEY_NAME;
    const privateKey = process.env.CDP_PRIVATE_KEY;
    
    if (!keyId || !privateKey) {
      return new Response(JSON.stringify({ 
        error: 'Server not configured',
        hint: 'CDP_KEY_NAME and CDP_PRIVATE_KEY environment variables must be set in Vercel',
        setup: 'Set CDP_KEY_NAME to the "id" and CDP_PRIVATE_KEY to the "privateKey" from your downloaded cdp_api_key.json'
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
      jwt = await generateJWT(keyId, privateKey);
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
