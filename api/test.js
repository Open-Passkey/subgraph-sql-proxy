// Test endpoint - Node.js runtime

import { SignJWT, importJWK, decodeJwt, decodeProtectedHeader } from 'jose';

function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateJWT(keyId, privateKeyBase64) {
  const now = Math.floor(Date.now() / 1000);
  
  const keyBytes = Buffer.from(privateKeyBase64, 'base64');
  const seed = keyBytes.subarray(0, 32);
  const publicKey = keyBytes.subarray(32);
  
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: seed.toString('base64url'),
    x: publicKey.toString('base64url'),
  };
  
  const key = await importJWK(jwk, 'EdDSA');
  
  return await new SignJWT({
    sub: keyId,
    iss: 'cdp',
    uris: ['POST api.cdp.coinbase.com/platform/v2/data/query/run']
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: keyId, typ: 'JWT', nonce: generateNonce() })
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + 120)
    .sign(key);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  try {
    const keyId = process.env.CDP_KEY_NAME;
    const privateKey = process.env.CDP_PRIVATE_KEY;
    
    if (!keyId || !privateKey) {
      return res.status(500).json({ 
        error: 'Not configured',
        keyIdSet: !!keyId,
        privateKeySet: !!privateKey,
      });
    }

    const jwt = await generateJWT(keyId, privateKey);
    const header = decodeProtectedHeader(jwt);
    const payload = decodeJwt(jwt);
    
    return res.status(200).json({ 
      success: true,
      jwtLength: jwt.length,
      header,
      payload,
      jwt
    });

  } catch (error) {
    return res.status(500).json({ 
      error: error.message,
      stack: error.stack
    });
  }
}
