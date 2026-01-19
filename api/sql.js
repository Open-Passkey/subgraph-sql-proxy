// Vercel Edge Function to proxy Coinbase SQL API requests with JWT authentication
// Set these environment variables in Vercel:
// - CDP_KEY_NAME: Your CDP API key ID (e.g., "06e27a55-d5f5-4e93-9e16-b33be1493380")
// - CDP_PRIVATE_KEY: Your CDP private key (base64 string from downloaded JSON)

export const config = {
  runtime: 'edge',
};

const COINBASE_SQL_API = 'https://api.cdp.coinbase.com/platform/v2/data/query/run';
const API_HOST = 'api.cdp.coinbase.com';

// Base64 to Base64URL conversion
function base64ToBase64Url(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Generate random hex nonce
function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate JWT for Coinbase API authentication using Ed25519
async function generateJWT(keyId, privateKeyBase64) {
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 120; // 2 minutes
  
  // Decode the base64 key (64 bytes: 32 seed + 32 public key)
  const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
  
  if (keyBytes.length !== 64) {
    throw new Error(`Invalid Ed25519 key length: expected 64 bytes, got ${keyBytes.length}`);
  }
  
  // Extract seed (first 32 bytes) and public key (last 32 bytes)
  const seed = keyBytes.slice(0, 32);
  const publicKey = keyBytes.slice(32);
  
  // Convert to base64url for JWK
  const dBase64Url = base64ToBase64Url(btoa(String.fromCharCode(...seed)));
  const xBase64Url = base64ToBase64Url(btoa(String.fromCharCode(...publicKey)));
  
  // Create JWK (JSON Web Key) format for Ed25519
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: dBase64Url,
    x: xBase64Url,
  };
  
  // JWT Header
  const header = {
    alg: 'EdDSA',
    kid: keyId,
    typ: 'JWT',
    nonce: generateNonce()
  };
  
  // JWT Payload per Coinbase docs
  const payload = {
    sub: keyId,
    iss: 'cdp',
    iat: now,
    nbf: now,
    exp: now + expiresIn,
    uris: [`POST ${API_HOST}/platform/v2/data/query/run`]
  };
  
  // Encode header and payload
  const headerB64 = base64ToBase64Url(btoa(JSON.stringify(header)));
  const payloadB64 = base64ToBase64Url(btoa(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  
  try {
    // Import the Ed25519 key using JWK format
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'Ed25519' },
      false,
      ['sign']
    );
    
    // Sign the JWT
    const signature = await crypto.subtle.sign(
      'Ed25519',
      key,
      new TextEncoder().encode(signingInput)
    );
    
    // Encode signature
    const sigB64 = base64ToBase64Url(btoa(String.fromCharCode(...new Uint8Array(signature))));
    
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
      console.log('Generated JWT (first 50 chars):', jwt.substring(0, 50));
    } catch (e) {
      return new Response(JSON.stringify({ 
        error: 'JWT generation failed', 
        details: e.message,
        keyIdPresent: !!keyId,
        privateKeyLength: privateKey?.length
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Forward to Coinbase SQL API with standard headers
    const response = await fetch(COINBASE_SQL_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwt}`,
        'User-Agent': 'CDP-SQL-Proxy/1.0',
        'Accept': 'application/json',
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
