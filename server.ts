import http from 'http';
import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { CONFIG } from './server/config';
import { runMigrations } from './server/database/db';
import { authMiddleware } from './server/middleware/auth';
import { apiRouter } from './server/api/routes';
import { agentRouter } from './server/agents/router';
import { securityWebSocketServer } from './server/websocket/wsServer';

dotenv.config();

const app = express();
const server = http.createServer(app);
app.set('trust proxy', 1);

// Allowed origins parser
const parseAllowedOrigins = (): string[] => {
  const raw = process.env.CORS_ORIGINS || CONFIG.CORS_ORIGINS || '';
  return raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
};
const allowedOrigins = parseAllowedOrigins();

// Security headers & Origin/CORS protection
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https:; connect-src 'self' ws: wss:; frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
  );

  const origin = req.headers.origin;
  if (origin) {
    const originLower = origin.toLowerCase();
    // Allow request only if origin matches allowed list or matches current host
    const isAllowed = allowedOrigins.includes('*') ||
      allowedOrigins.includes(originLower) ||
      originLower === `https://${req.headers.host?.toLowerCase()}` ||
      originLower === `http://${req.headers.host?.toLowerCase()}`;

    if (isAllowed) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Organization-Id');
      res.setHeader('Access-Control-Max-Age', '86400');
    }
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Basic middleware. Keep the raw body around so the agent request signature
// can be verified against the exact bytes the endpoint signed.
app.use(express.json({
  limit: '10mb',
  verify: (req, _res, buf) => {
    (req as express.Request & { rawBody?: Buffer }).rawBody = Buffer.from(buf);
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve favicon.ico
app.get('/favicon.ico', (_req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'favicon.ico'));
});

// Run DB migrations
try {
  runMigrations();
} catch (err) {
  console.error('[OAT SECURITY] Database migration error:', err);
}

// Tenant & Auth context middleware
app.use(authMiddleware);

import { startHealthMonitor } from './server/services/systemHealthService';
import { startEndpointMonitor } from './server/services/endpointConnectionService';
import { startRealtimeSnapshotService } from './server/services/realtimeSnapshotService';
import { startWazuhManagerListener } from './server/services/wazuhSiemPipeline';

// Start continuous real-time health telemetry monitor, endpoint connectivity monitor & Wazuh SIEM listener
try {
  startHealthMonitor();
  startEndpointMonitor();
  startRealtimeSnapshotService();
  startWazuhManagerListener();
} catch (err) {
  console.warn('[OAT SECURITY] Service monitor warning:', err);
}

import { superAdminRouter } from './server/superAdmin/router';

// Mount REST API routes
app.use('/api/super-admin', superAdminRouter);
app.use('/api/agents', agentRouter);
app.use('/api', apiRouter);

// Global Error Handler for API routes
app.use((err: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[OAT SECURITY ERROR]:', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({
    error: err?.message || 'Internal Server Error'
  });
});

// Initialize WebSocket server on HTTP server (/ws)
securityWebSocketServer.init(server);

// Return 404 for unauthenticated probe/management paths (metrics, actuator) and nonexistent admin paths
app.all(['/metrics', '/metrics/*', '/actuator', '/actuator/*'], (_req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Explicitly protect /dashboard so direct API/browser access without auth gets rejected
app.all(['/dashboard', '/dashboard/*'], (req, res, next) => {
  if (!(req as any).user) {
    // If request accepts HTML (direct browser navigation), let it fall through to SPA router which redirects to /login.
    // If it's an API/fetch/scanner probe expecting JSON or non-HTML, return 401 Unauthorized.
    const acceptHeader = req.headers.accept || '';
    if (!acceptHeader.includes('text/html')) {
      return res.status(401).json({ error: 'Authentication Required' });
    }
  }
  next();
});

// Sensitive admin/administrator/api/admin probes without session get 401 Unauthorized
app.all(['/admin', '/admin/*', '/administrator', '/administrator/*', '/api/admin', '/api/admin/*'], (req, res, next) => {
  // If user is not authenticated on these paths, reject immediately with 401
  if (!(req as any).user) {
    return res.status(401).json({ error: 'Authentication Required' });
  }
  next();
});

// Vite middleware & SPA Handling
async function startApp() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(CONFIG.PORT, CONFIG.HOST, () => {
    const displayHost = CONFIG.HOST === '0.0.0.0' || CONFIG.HOST === '::' ? 'localhost' : CONFIG.HOST;
    console.log(`[OAT SECURITY] Enterprise Server running on http://${displayHost}:${CONFIG.PORT}`);
    console.log(`[OAT SECURITY] WebSocket active at ws://${displayHost}:${CONFIG.PORT}/ws`);
    console.log(`[OAT SECURITY] Agent enrollment at http://${displayHost}:${CONFIG.PORT}/api/agents/enroll`);
  });
}

startApp().catch(err => {
  console.error('[OAT SECURITY] Fatal server startup error:', err);
  process.exit(1);
});
