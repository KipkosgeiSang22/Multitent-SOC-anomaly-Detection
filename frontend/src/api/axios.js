import axios from 'axios';

// ─── Axios instance ────────────────────────────────────────────────────────────
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  withCredentials: true,       // send httpOnly refresh cookie on every request
  headers: { 'Content-Type': 'application/json' },
});

// ─── Token injection ───────────────────────────────────────────────────────────
// Access token lives in memory only (never localStorage). The sto roe exposes a
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
    if (error) reject(error);// refresh failed — tell all queued requests to fail too, only the waiting requests that were queued
    else resolve(token); // refresh succeeded — give all queued requests the new token
  });
  _refreshQueue = [];// clear the queue either way
}

let _setAccessToken = () => {};
let _clearAuth = () => {};

export function registerAuthActions({ setAccessToken, clearAuth }) {
  _setAccessToken = setAccessToken;
  _clearAuth = clearAuth;
}
//the interceptor's single responsibility is: make token expiry invisible to the rest of the app.
api.interceptors.response.use(//api.interceptors.response.use(successCallback, errorCallback)
  (response) => response, // success callback — runs on every successful response and successful responses are routed automatically; just pass the response through unchanged, success callback retry worked → ends here, response flows normally
  async (error) => {// error callback — runs on every failed response intercept and handle errors, failed responses are routed to it automatically, errorcallback  retry failed → captured here
    const original = error.config;// has the original request; url, headers etc

    // Only handle 401 errors. Avoid infinite loops with _retry flag.
    if (error.response?.status !== 401 || original._retry) {
      return Promise.reject(error);
    }

    // Don't try to refresh for auth endpoints themselves
    const skipRefreshPaths = ['/auth/login', '/auth/refresh', '/auth/logout'];
    if (skipRefreshPaths.some((p) => original.url?.includes(p))) {
      return Promise.reject(error);
    }

    if (_refreshing) {// 1. park and wait
      // Queue this request until refresh completes
      return new Promise((resolve, reject) => {
        _refreshQueue.push({ resolve, reject }); // suspend here, resolve and reject are both functions of promise object, and they have values, either null for both or error-> reject, token-> resolve
      }).then((token) => {// 2. runs when resolve(token) is called, runs when it _refreshing has completed
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);      // 3. retry the original request
      });// this is same user session, for if there are more than 2 retries, they are get one token from the 1 retry, hence all the following in the queue just et the same token
    }

    original._retry = true;
    _refreshing = true;

    try {
      // Refresh cookie is sent automatically (withCredentials: true).
      // Use bare axios (not the api instance) to avoid re-triggering this
      // interceptor and causing an infinite loop.
      const { data } = await axios.post(
        `${api.defaults.baseURL}/auth/refresh`,//manually grabs the url from the api instance
        {},//The request body is an empty object. The refresh endpoint doesn't need any data in the body because the refresh token travels automatically as an httpOnly cookie, not in the body.
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
      window.location.href = '/login';// wipes current page, navigates to login
// also clears all JS memory including the Zustand store
      return Promise.reject(refreshError);// this is the FIRST request that triggered the 401, the original request gets this
    } finally {
      _refreshing = false;
    }
  }
);
// User is logged in
//   → access token expires
//   → user's request hits 401
//   → interceptor error callback fires
//   → is the failed request's URL in skipRefreshPaths? 
//       → NO, it was something like /data or /users/me
//   → so it falls through to the refresh logic
//   → calls /auth/refresh 

export default api;
