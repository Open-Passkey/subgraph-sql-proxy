// Test endpoint to verify JWT generation
export const config = {
  runtime: 'edge',
};

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
  
  const header = {
    alg: 'EdDSA',
    kid: keyId,
    typ: 'JWT',
    nonce: generateNonce()
  };
  
  const payload = {
    sub: keyId,
    iss: 'cdp',
    iat: now,
    nbf: now,
    exp: now + expiresIn,
    uris: [`POST api.cdp.coinbase.com/platform/v2/data/query/run`]
  };
  
  const headerB64 = base64ToBase64Url(btoa(JSON.stringify(header)));
  const payloadB64 = base64ToBase64Url(btoa(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'Ed25519',
    key,
    new TextEncoder().encode(signingInput)
  );
  
  const sigB64 = base64ToBase64Url(btoa(String.fromCharCode(...new Uint8Array(signature))));
  
  return `${signingInput}.${sigB64}`;
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
    
    // Decode and display JWT parts (without signature)
    const [headerB64, payloadB64] = jwt.split('.');
    const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    
    return new Response(JSON.stringify({ 
      success: true,
      jwtLength: jwt.length,
      header,
      payload,
      jwtPreview: jwt.substring(0, 100) + '...'
    }, null, 2), { headers: corsHeaders });

  } catch (error) {
    return new Response(JSON.stringify({ 
      error: error.message,
      stack: error.stack
    }), { status: 500, headers: corsHeaders });
  }
}
