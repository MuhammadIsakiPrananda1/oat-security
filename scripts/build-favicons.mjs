import fs from 'fs';
import path from 'path';
import http from 'http';
import { spawn } from 'child_process';
import { createIco } from './ico-builder.mjs';

const publicDir = path.resolve('public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

// Master SVG
const svgContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="sq-grad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#FFFFFF" />
      <stop offset="100%" stop-color="#F8FAFC" />
    </linearGradient>
  </defs>

  <!-- Squircle Base with rounded corners -->
  <rect 
    x="16" 
    y="16" 
    width="480" 
    height="480" 
    rx="128" 
    ry="128" 
    fill="url(#sq-grad)" 
    stroke="#D4D4D8" 
    stroke-width="8"
  />

  <!-- OAT Security Shield Halved Icon -->
  <g transform="translate(256, 256) scale(0.52) translate(-256, -256)">
    <path 
      fill="#09090b" 
      d="M256 0c4.6 0 9.2 1 13.4 2.9L457.8 82.8c22 9.3 38.4 31 38.3 57.2-.5 99.2-41.3 280.7-213.6 363.2-16.7 8-36.1 8-52.8 0-172.4-82.5-213.1-264-213.6-363.2-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.9 1 251.4 0 256 0zm0 66.8l0 378.1c138-66.8 175.1-214.8 176-303.4l-176-74.6 0 0z" 
    />
  </g>
</svg>
`;

fs.writeFileSync(path.join(publicDir, 'favicon.svg'), svgContent.trim(), 'utf-8');
console.log('✓ Created public/favicon.svg');

// Web App Manifest
const webManifest = {
  name: "OAT SECURITY - Enterprise Platform",
  short_name: "OAT SECURITY",
  description: "Enterprise Cybersecurity Platform, WAF, Threat Detection & Monitoring",
  icons: [
    {
      src: "/favicon-32x32.png",
      sizes: "32x32",
      type: "image/png"
    },
    {
      src: "/android-chrome-192x192.png",
      sizes: "192x192",
      type: "image/png"
    },
    {
      src: "/android-chrome-512x512.png",
      sizes: "512x512",
      type: "image/png"
    }
  ],
  theme_color: "#09090b",
  background_color: "#09090b",
  display: "standalone"
};

fs.writeFileSync(path.join(publicDir, 'site.webmanifest'), JSON.stringify(webManifest, null, 2), 'utf-8');
console.log('✓ Created public/site.webmanifest');

// Start temporary server to render canvases with Edge
const savedImages = {};
const sizesToRender = [16, 32, 48, 180, 192, 512];

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html>
<body>
<script>
  const svgText = ${JSON.stringify(svgContent)};
  const blob = new Blob([svgText], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const img = new Image();
  img.onload = async () => {
    const sizes = ${JSON.stringify(sizesToRender)};
    for (const size of sizes) {
      const canvas = document.createElement('canvas');
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext('2d');
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, 0, 0, size, size);
      const dataUrl = canvas.toDataURL('image/png');
      const base64 = dataUrl.replace(/^data:image\\/png;base64,/, '');
      await fetch('/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ size, base64 })
      });
    }
    await fetch('/done', { method: 'POST' });
  };
  img.src = url;
</script>
</body>
</html>`);
    return;
  }

  if (req.method === 'POST' && req.url === '/upload') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const { size, base64 } = JSON.parse(body);
      const buf = Buffer.from(base64, 'base64');
      savedImages[size] = buf;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    return;
  }

  if (req.method === 'POST' && req.url === '/done') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    finish();
    return;
  }

  res.writeHead(404).end();
});

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  console.log(`Render server listening on port ${port}...`);

  const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  const child = spawn(edgePath, [
    '--headless',
    '--no-sandbox',
    '--disable-gpu',
    `http://127.0.0.1:${port}/`
  ]);

  child.on('error', err => {
    console.error('Failed to spawn Edge:', err);
    process.exit(1);
  });
});

function finish() {
  console.log('Received rendered PNGs. Writing output files...');
  
  // Write specific PNG files
  if (savedImages[16]) fs.writeFileSync(path.join(publicDir, 'favicon-16x16.png'), savedImages[16]);
  if (savedImages[32]) fs.writeFileSync(path.join(publicDir, 'favicon-32x32.png'), savedImages[32]);
  if (savedImages[48]) fs.writeFileSync(path.join(publicDir, 'favicon-48x48.png'), savedImages[48]);
  if (savedImages[180]) fs.writeFileSync(path.join(publicDir, 'apple-touch-icon.png'), savedImages[180]);
  if (savedImages[192]) fs.writeFileSync(path.join(publicDir, 'android-chrome-192x192.png'), savedImages[192]);
  if (savedImages[512]) fs.writeFileSync(path.join(publicDir, 'android-chrome-512x512.png'), savedImages[512]);

  console.log('✓ Generated favicon-16x16.png');
  console.log('✓ Generated favicon-32x32.png');
  console.log('✓ Generated favicon-48x48.png');
  console.log('✓ Generated apple-touch-icon.png');
  console.log('✓ Generated android-chrome-192x192.png');
  console.log('✓ Generated android-chrome-512x512.png');

  // Build multi-res ICO (16, 32, 48)
  const icoBuffers = [
    { width: 16, height: 16, buffer: savedImages[16] },
    { width: 32, height: 32, buffer: savedImages[32] },
    { width: 48, height: 48, buffer: savedImages[48] }
  ].filter(item => !!item.buffer);

  const icoBuf = createIco(icoBuffers);
  fs.writeFileSync(path.join(publicDir, 'favicon.ico'), icoBuf);
  console.log('✓ Generated multi-resolution public/favicon.ico');

  server.close(() => {
    console.log('All favicons generated successfully!');
    process.exit(0);
  });
}
