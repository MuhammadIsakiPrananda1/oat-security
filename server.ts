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

// Security headers & Origin/CORS protection
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Organization-Id');
    res.setHeader('Access-Control-Max-Age', '86400');
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
