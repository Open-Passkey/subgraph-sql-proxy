export const config = {
  runtime: 'edge',
};

export default async function handler(request) {
  return new Response(JSON.stringify({ 
    status: 'ok',
    message: 'Coinbase SQL API Proxy',
    endpoint: '/api/sql',
    method: 'POST',
    headers: 'Authorization: Bearer <your-cdp-api-key>'
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
