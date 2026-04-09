const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PROXY_SECRET = process.env.PROXY_SECRET || 'emissordenotasfiscais1';

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Auth
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

      // Sign RPS + add XML-DSIG if requested and certificate is provided (São Paulo format)
      if (signRps && certBase64) {
        try {
          finalSoapBody = signRpsAndXmlDsig(soapBody, certBase64, certPassword || '');
          console.log('[proxy] RPS + XML-DSIG signed successfully');
        } catch (signErr) {
          console.error('[proxy] Signing failed:', signErr.message);
          console.error('[proxy] Stack:', signErr.stack);
        }
      }

      const parsed = new URL(targetUrl);

      // SOAP 1.2 uses application/soap+xml, SOAP 1.1 uses text/xml
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

      // Only add SOAPAction header for SOAP 1.1
      if (!soap12) {
        options.headers['SOAPAction'] = soapAction;
      }

      // Add client certificate (mTLS) if provided
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

// Sign data using RSA-SHA1 with PFX certificate
function rsaSha1Sign(data, certBase64, certPassword, encoding = 'ascii') {
  const sign = crypto.createSign('SHA1');
  sign.update(data, encoding);

  const pfxBuffer = Buffer.from(certBase64, 'base64');
  return sign.sign({
    key: pfxBuffer,
    passphrase: certPassword,
    format: 'der',
    type: 'pkcs12',
  }, 'base64');
}

// Get X509 certificate in DER base64 from PFX
function getX509CertBase64(certBase64, certPassword) {
  let forge;
  try {
    forge = require('node-forge');
  } catch (e) {
    return ''; // node-forge not available
  }

  const pfxAsn1 = forge.asn1.fromDer(forge.util.decode64(certBase64));
  const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, certPassword || '');

  for (const safeContents of p12.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      if (safeBag.type === forge.pki.oids.certBag && safeBag.cert) {
        const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(safeBag.cert)).getBytes();
        return forge.util.encode64(certDer);
      }
    }
  }
  return '';
}

// Sign RPS and add XML-DSIG for São Paulo NFS-e
function signRpsAndXmlDsig(soapBody, certBase64, certPassword) {
  // Extract the CDATA content (PedidoEnvioLoteRPS XML)
  const cdataMatch = soapBody.match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  if (!cdataMatch) return soapBody;

  let pedidoXml = cdataMatch[1];

  // === STEP 1: Sign the RPS ===
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

  // Check if tomador is CPF or CNPJ
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
      cpfCnpjTomador = '00000000000000';
    }
  } else {
    tipoTomador = '3';
    cpfCnpjTomador = '00000000000000';
  }

  // Build 86-char signature string per SP manual v2.8.2, section 4.3.2
  const sigString = inscricao + serie + numero + dataEmissao + tributacao +
    status + issRetido + valorServicos + valorDeducoes + codigoServico +
    tipoTomador + cpfCnpjTomador;

  console.log('[proxy] RPS sig string (' + sigString.length + ' chars):', sigString);

  // RSA-SHA1 sign the RPS string
  const rpsSignature = rsaSha1Sign(sigString, certBase64, certPassword, 'ascii');
  console.log('[proxy] RPS signature (first 60):', rpsSignature.substring(0, 60));

  // Replace empty <Assinatura></Assinatura> with the computed signature
  pedidoXml = pedidoXml.replace(
    /<Assinatura><\/Assinatura>/,
    `<Assinatura>${rpsSignature}</Assinatura>`
  );

  // === STEP 2: Build XML-DSIG (W3C Signature) ===
  const digestHash = crypto.createHash('sha1').update(pedidoXml, 'utf8').digest('base64');

  const signedInfoCanonical = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
    '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>' +
    '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>' +
    '<Reference URI="">' +
    '<Transforms>' +
    '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>' +
    '<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></Transform>' +
    '</Transforms>' +
    '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' +
    '<DigestValue>' + digestHash + '</DigestValue>' +
    '</Reference>' +
    '</SignedInfo>';

  const signatureValue = rsaSha1Sign(signedInfoCanonical, certBase64, certPassword, 'utf8');
  const x509Base64 = getX509CertBase64(certBase64, certPassword);

  console.log('[proxy] XML-DSIG DigestValue:', digestHash);
  console.log('[proxy] XML-DSIG SignatureValue length:', signatureValue.length);

  const signatureElement = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
    '<SignedInfo>' +
    '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>' +
    '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>' +
    '<Reference URI="">' +
    '<Transforms>' +
    '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>' +
    '<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></Transform>' +
    '</Transforms>' +
    '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>' +
    '<DigestValue>' + digestHash + '</DigestValue>' +
    '</Reference>' +
    '</SignedInfo>' +
    '<SignatureValue>' + signatureValue + '</SignatureValue>' +
    '<KeyInfo><X509Data><X509Certificate>' + x509Base64 + '</X509Certificate></X509Data></KeyInfo>' +
    '</Signature>';

  pedidoXml = pedidoXml.replace('</PedidoEnvioLoteRPS>', signatureElement + '</PedidoEnvioLoteRPS>');

  console.log('[proxy] Final pedidoXml length:', pedidoXml.length);

  return soapBody.replace(
    /<!\[CDATA\[[\s\S]*?\]\]>/,
    `<![CDATA[${pedidoXml}]]>`
  );
}

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`NFS-e Proxy running on port ${PORT}`));
