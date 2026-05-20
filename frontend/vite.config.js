import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// ─── Proxy strategy ────────────────────────────────────────────────────────────
//
// PROBLEM: Many API paths (/admin/anomalies, /analyst/events, etc.) are
// identical to React Router page paths. A blanket proxy rule would forward
// page reloads to FastAPI, which returns {"detail":"Not Found"} instead of
// index.html — breaking hard reloads on every page except those with no
// matching proxy entry.
//
// SOLUTION: Use Vite's `bypass` function on every proxy rule.
// - API calls from axios always include `Accept: application/json`
// - Page navigations (browser reloads) send `Accept: text/html,...`
//
// If the request looks like a page navigation (no application/json in Accept),
// return '/' to tell Vite to serve index.html instead of proxying.
// This works for ALL paths with zero backend changes.
//
// /auth is the only safe broad proxy (no React routes live under /auth).
// Everything else uses the bypass guard.

function apiOnly(req, _res, _options) {
  const accept = req.headers['accept'] || '';
  // If the browser is asking for a page (text/html), serve index.html.
  // Axios API calls always include application/json in their Accept header.
  if (!accept.includes('application/json')) {
    return '/';   // tells Vite: serve index.html, do not proxy
  }
  // Otherwise: fall through and proxy to the backend.
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // ── Auth: safe to proxy broadly — no React routes under /auth ──────────
      '/auth': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },

      // ── Standalone backend routers (no React route conflicts) ───────────────
      '/rules':    { target: 'http://localhost:8000', changeOrigin: true },
      '/retrain':  { target: 'http://localhost:8000', changeOrigin: true },
      '/graylog':  { target: 'http://localhost:8000', changeOrigin: true },
      '/payments': { target: 'http://localhost:8000', changeOrigin: true },

      // ── Client API paths (conflict with /client/* React routes) ────────────
      '/client': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: apiOnly,
      },

      // ── Analyst API paths (conflict with /analyst/* React routes) ──────────
      '/analyst': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: apiOnly,
      },

      // ── Admin API paths (conflict with /admin/* React routes) ──────────────
      '/admin': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: apiOnly,
      },
    },
  },
});