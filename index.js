const https = require('https');
const http = require('http');
const crypto = require('crypto');
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
      const { targetUrl, soapAction, soapBody, certBase64, certPassword, signRps, soap12 } = JSON.parse(body);
      
      let finalSoapBody = soapBody;
      
      if (signRps && certBase64) {
        try {
          finalSoapBody = signRpsInXml(soapBody, certBase64, certPassword || '');
          console.log('[proxy] RPS signed successfully');
        } catch (signErr) {
          console.error('[proxy] RPS signing failed:', signErr.message);
        }
      }
      
      const parsed = new URL(targetUrl);

      const contentType = soap12
        ? `application/soap+xml; charset=utf-8; action="${soapAction}"`
        : 'text/xml; charset=utf-8';

      const options = {
        hostname: parsed.hostname,
        port: 443,
        path: parsed.pathname + (parsed.search || ''),
        method: 'POST',
        headers: {
          'Content-Type': contentType,
          'Content-Length': Buffer.byteLength(finalSoapBody, 'utf8'),
        },
      };

      if (!soap12) {
        options.headers['SOAPAction'] = soapAction;
      }

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

      proxyReq.write(finalSoapBody);
      proxyReq.end();
    } catch (e) {
      res.writeHead(400);
      res.end(JSON.stringify({ error: e.message }));
    }
  });
});

function signRpsInXml(soapBody, certBase64, certPassword) {
  const cdataMatch = soapBody.match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  if (!cdataMatch) return soapBody;
  
  let pedidoXml = cdataMatch[1];
  
  const getTag = (xml, tag) => {
    const m = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
    return m ? m[1] : '';
  };
  
  const inscricao = getTag(pedidoXml, 'InscricaoPrestador').padStart(8, '0');
  const serie = getTag(pedidoXml, 'SerieRPS').padEnd(5, ' ');
  const numero = getTag(pedidoXml, 'NumeroRPS').padStart(12, '0');
  const dataEmissao = getTag(pedidoXml, 'DataEmissao').replace(/-/g, '');
  const tributacao = getTag(pedidoXml, 'TributacaoRPS');
  const status = getTag(pedidoXml, 'StatusRPS');
  const issRetido = getTag(pedidoXml, 'ISSRetido') === 'true' ? 'S' : 'N';
  const valorServicos = parseFloat(getTag(pedidoXml, 'ValorServicos') || '0')
    .toFixed(2).replace('.', '').padStart(15, '0');
  const valorDeducoes = parseFloat(getTag(pedidoXml, 'ValorDeducoes') || '0')
    .toFixed(2).replace('.', '').padStart(15, '0');
  const codigoServico = getTag(pedidoXml, 'CodigoServico').padStart(5, '0');
  
  const tomadorBlock = pedidoXml.match(/<CPFCNPJTomador>([\s\S]*?)<\/CPFCNPJTomador>/);
  let tipoTomador, cpfCnpjTomador;
  if (tomadorBlock) {
    const tomadorContent = tomadorBlock[1];
    const tomCpf = tomadorContent.match(/<CPF>([^<]*)<\/CPF>/);
    const tomCnpj = tomadorContent.match(/<CNPJ>([^<]*)<\/CNPJ>/);
    if (tomCpf) {
      tipoTomador = '1';
      cpfCnpjTomador = tomCpf[1].padStart(14, '0');
    } else if (tomCnpj) {
      tipoTomador = '2';
      cpfCnpjTomador = tomCnpj[1].padStart(14, '0');
    } else {
      tipoTomador = '3';
      cpfCnpjTomador = ''.padStart(14, '0');
    }
  } else {
    tipoTomador = '3';
    cpfCnpjTomador = ''.padStart(14, '0');
  }
  
  const sigString = inscricao + serie + numero + dataEmissao + tributacao + 
    status + issRetido + valorServicos + valorDeducoes + codigoServico + 
    tipoTomador + cpfCnpjTomador;
  
  console.log('[proxy] Signature string (' + sigString.length + ' chars):', sigString);
  
  const pfxBuffer = Buffer.from(certBase64, 'base64');
  const sign = crypto.createSign('SHA1');
  sign.update(sigString, 'ascii');
  
  const signature = sign.sign({
    key: pfxBuffer,
    passphrase: certPassword,
    format: 'der',
    type: 'pkcs12',
  }, 'base64');
  
  pedidoXml = pedidoXml.replace(
    /<Assinatura><\/Assinatura>/,
    `<Assinatura>${signature}</Assinatura>`
  );
  
  return soapBody.replace(
    /<!\[CDATA\[[\s\S]*?\]\]>/,
    `<![CDATA[${pedidoXml}]]>`
  );
}

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`NFS-e Proxy running on port ${PORT}`));
