import axios from 'axios';

// ─── Axios instance ────────────────────────────────────────────────────────────
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  withCredentials: true,       // send httpOnly refresh cookie on every request
  headers: { 'Content-Type': 'application/json' },
});

// ─── Token injection ───────────────────────────────────────────────────────────
// Access token lives in memory only (never localStorage). The store exposes a
// getter so the interceptor can always read the latest value.
let _getAccessToken = () => null;

export function registerTokenGetter(fn) {
  _getAccessToken = fn;
}

api.interceptors.request.use((config) => {
  const token = _getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ─── Refresh-on-401 interceptor ───────────────────────────────────────────────
let _refreshing = false;
let _refreshQueue = [];          // queued requests waiting for refresh

function processQueue(error, token = null) {
  _refreshQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else resolve(token);
  });
  _refreshQueue = [];
}

let _setAccessToken = () => {};
let _clearAuth = () => {};

export function registerAuthActions({ setAccessToken, clearAuth }) {
  _setAccessToken = setAccessToken;
  _clearAuth = clearAuth;
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;

    // Only handle 401 errors. Avoid infinite loops with _retry flag.
    if (error.response?.status !== 401 || original._retry) {
      return Promise.reject(error);
    }

    // Don't try to refresh for auth endpoints themselves
    const skipRefreshPaths = ['/auth/login', '/auth/refresh', '/auth/logout'];
    if (skipRefreshPaths.some((p) => original.url?.includes(p))) {
      return Promise.reject(error);
    }

    if (_refreshing) {
      // Queue this request until refresh completes
      return new Promise((resolve, reject) => {
        _refreshQueue.push({ resolve, reject });
      }).then((token) => {
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      });
    }

    original._retry = true;
    _refreshing = true;

    try {
      // Refresh cookie is sent automatically (withCredentials: true).
      // Use bare axios (not the api instance) to avoid re-triggering this
      // interceptor and causing an infinite loop.
      const { data } = await axios.post(
        `${api.defaults.baseURL}/auth/refresh`,
        {},
        { withCredentials: true }
      );

      const newToken = data.access_token;
      _setAccessToken(newToken);
      processQueue(null, newToken);

      original.headers.Authorization = `Bearer ${newToken}`;
      return api(original);
    } catch (refreshError) {
      processQueue(refreshError, null);
      _clearAuth();
      window.location.href = '/login';
      return Promise.reject(refreshError);
    } finally {
      _refreshing = false;
    }
  }
);

export default api;
