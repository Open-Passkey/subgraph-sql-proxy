// Vercel Edge Function to proxy Coinbase SQL API requests with JWT authentication
// Using jose library (same as Coinbase SDK)

import { SignJWT, importJWK } from 'jose';

export const config = {
  runtime: 'edge',
};

const COINBASE_SQL_API = 'https://api.cdp.coinbase.com/platform/v2/data/query/run';
const API_HOST = 'api.cdp.coinbase.com';

// Generate random hex nonce
function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Base64 to Base64URL (without padding)
function base64ToBase64Url(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Generate JWT for Coinbase API authentication using Ed25519
async function generateJWT(keyId, privateKeyBase64) {
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 120;
  
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
  
  // Import the key using jose
  const key = await importJWK(jwk, 'EdDSA');
  
  // Build JWT claims
  const claims = {
    sub: keyId,
    iss: 'cdp',
    uris: [`POST ${API_HOST}/platform/v2/data/query/run`]
  };
  
  // Sign and return JWT
  return await new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', kid: keyId, typ: 'JWT', nonce: generateNonce() })
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + expiresIn)
    .sign(key);
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
        hint: 'Set CDP_KEY_NAME and CDP_PRIVATE_KEY in Vercel environment variables'
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

    // Generate JWT using jose library
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

    // Forward to Coinbase SQL API with browser-like headers to pass Cloudflare
    const response = await fetch(COINBASE_SQL_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwt}`,
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Origin': 'https://portal.cdp.coinbase.com',
        'Referer': 'https://portal.cdp.coinbase.com/',
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
