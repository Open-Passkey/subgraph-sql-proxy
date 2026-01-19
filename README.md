# Coinbase SQL API Proxy

A Vercel Edge Function that proxies requests to the Coinbase CDP SQL API with JWT authentication.

## Setup

1. **Create a CDP Secret API Key**:
   - Go to [CDP Portal](https://portal.cdp.coinbase.com/)
   - Navigate to API Keys → Secret API Keys
   - Create a new key with ECDSA algorithm
   - Save the Key Name and Private Key

2. **Set Environment Variables in Vercel**:
   - Go to your Vercel project → Settings → Environment Variables
   - Add the following variables:
     - `CDP_KEY_NAME`: Your CDP API key name (e.g., `organizations/xxx/apiKeys/xxx`)
     - `CDP_PRIVATE_KEY`: Your CDP private key in PEM format

3. **Deploy**:
   ```bash
   vercel --prod
   ```

## Usage

Make a POST request to `/api/sql`:

```bash
curl -X POST https://your-deployment.vercel.app/api/sql \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM base.events LIMIT 1"}'
```

## Response Format

```json
{
  "result": [...],
  "metadata": {
    "cached": false,
    "executionTimeMs": 145,
    "rowCount": 1
  }
}
```

## Supported Tables

- `base.events` - Decoded event logs
- `base.transactions` - Transaction data
- `base.blocks` - Block information
- `base.transfers` - Token transfer events
- `base.encoded_logs` - Encoded log data

## Security

- The CDP Secret API Key is stored securely in Vercel environment variables
- JWT tokens are generated server-side and never exposed to clients
- CORS is configured to allow requests from any origin (configure as needed)
