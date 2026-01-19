// Test endpoint to verify JWT generation using jose library

import { SignJWT, importJWK, decodeJwt, decodeProtectedHeader } from 'jose';

export const config = {
  runtime: 'edge',
};

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

// Generate JWT using jose library (same as Coinbase SDK)
async function generateJWT(keyId, privateKeyBase64) {
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 120;
  
  const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
  
  if (keyBytes.length !== 64) {
    throw new Error(`Invalid Ed25519 key length: expected 64 bytes, got ${keyBytes.length}`);
  }
  
  const seed = keyBytes.slice(0, 32);
  const publicKey = keyBytes.slice(32);
  
  const dBase64Url = base64ToBase64Url(btoa(String.fromCharCode(...seed)));
  const xBase64Url = base64ToBase64Url(btoa(String.fromCharCode(...publicKey)));
  
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: dBase64Url,
    x: xBase64Url,
  };
  
  const key = await importJWK(jwk, 'EdDSA');
  
  const claims = {
    sub: keyId,
    iss: 'cdp',
    uris: [`POST api.cdp.coinbase.com/platform/v2/data/query/run`]
  };
  
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
    'Content-Type': 'application/json',
  };

  try {
    const keyId = process.env.CDP_KEY_NAME;
    const privateKey = process.env.CDP_PRIVATE_KEY;
    
    if (!keyId || !privateKey) {
      return new Response(JSON.stringify({ 
        error: 'Not configured',
        keyIdSet: !!keyId,
        privateKeySet: !!privateKey,
      }), { status: 500, headers: corsHeaders });
    }

    const jwt = await generateJWT(keyId, privateKey);
    
    // Decode JWT parts using jose
    const header = decodeProtectedHeader(jwt);
    const payload = decodeJwt(jwt);
    
    return new Response(JSON.stringify({ 
      success: true,
      jwtLength: jwt.length,
      header,
      payload,
      jwt: jwt  // Include full JWT for testing
    }, null, 2), { headers: corsHeaders });

  } catch (error) {
    return new Response(JSON.stringify({ 
      error: error.message,
      stack: error.stack
    }), { status: 500, headers: corsHeaders });
  }
}
