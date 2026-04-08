const https = require('https');
const http = require('http');
const { URL } = require('url');

const PROXY_SECRET = process.env.PROXY_SECRET || 'sua-chave-secreta-aqui';

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  const authHeader = req.headers['x-proxy-secret'];
  if (authHeader !== PROXY_SECRET) {
    res.writeHead(401); res.end('Unauthorized'); return;
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try {
      const { targetUrl, soapAction, soapBody, certBase64, certPassword } = JSON.parse(body);
      const parsed = new URL(targetUrl);

      const options = {
        hostname: parsed.hostname,
        port: 443,
        path: parsed.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          'SOAPAction': soapAction,
          'Content-Length': Buffer.byteLength(soapBody),
        },
      };

      if (certBase64) {
        options.pfx = Buffer.from(certBase64, 'base64');
        options.passphrase = certPassword || '';
        options.rejectUnauthorized = false;
      }

      const proxyReq = https.request(options, (proxyRes) => {
        let responseBody = '';
        proxyRes.on('data', chunk => responseBody += chunk);
        proxyRes.on('end', () => {
          res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: proxyRes.statusCode, body: responseBody }));
        });
      });

      proxyReq.on('error', (err) => {
        res.writeHead(502);
        res.end(JSON.stringify({ error: err.message }));
      });

      proxyReq.write(soapBody);
      proxyReq.end();
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: e.message }));
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`NFS-e Proxy running on port ${PORT}`));
