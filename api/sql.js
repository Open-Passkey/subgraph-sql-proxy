// Vercel Serverless Function (Node.js runtime) to proxy Coinbase SQL API

import { SignJWT, importJWK } from 'jose';

// Generate random hex nonce
function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Base64 to Base64URL
function base64ToBase64Url(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Generate JWT
async function generateJWT(keyId, privateKeyBase64) {
  const now = Math.floor(Date.now() / 1000);
  
  const keyBytes = Buffer.from(privateKeyBase64, 'base64');
  
  if (keyBytes.length !== 64) {
    throw new Error(`Invalid Ed25519 key length: ${keyBytes.length}`);
  }
  
  const seed = keyBytes.subarray(0, 32);
  const publicKey = keyBytes.subarray(32);
  
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: seed.toString('base64url'),
    x: publicKey.toString('base64url'),
  };
  
  const key = await importJWK(jwk, 'EdDSA');
  
  const claims = {
    sub: keyId,
    iss: 'cdp',
    uris: ['POST api.cdp.coinbase.com/platform/v2/data/query/run']
  };
  
  return await new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA', kid: keyId, typ: 'JWT', nonce: generateNonce() })
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + 120)
    .sign(key);
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const keyId = process.env.CDP_KEY_NAME;
    const privateKey = process.env.CDP_PRIVATE_KEY;
    
    if (!keyId || !privateKey) {
      return res.status(500).json({ 
        error: 'Server not configured',
        hint: 'Set CDP_KEY_NAME and CDP_PRIVATE_KEY in Vercel environment variables'
      });
    }

    const { sql, cache } = req.body;

    if (!sql) {
      return res.status(400).json({ error: 'Missing required field: sql' });
    }

    // Generate JWT
    const jwt = await generateJWT(keyId, privateKey);

    // Forward to Coinbase SQL API
    const response = await fetch('https://api.cdp.coinbase.com/platform/v2/data/query/run', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwt}`,
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        sql,
        cache: cache || { maxAgeMs: 5000 }
      }),
    });

    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('application/json')) {
      const data = await response.json();
      return res.status(response.status).json(data);
    } else {
      const text = await response.text();
      return res.status(response.status).json({ 
        error: 'Coinbase API returned non-JSON response',
        status: response.status,
        preview: text.substring(0, 500)
      });
    }

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
