import { create } from 'zustand';
import { registerTokenGetter, registerAuthActions } from '../api/axios';
import api from '../api/axios';

// ─── Auth Store ────────────────────────────────────────────────────────────────
// Access token NEVER touches localStorage or sessionStorage.
//
// BACKEND NOTES (verified against actual auth.py — Session 13):
//
//   POST /auth/login response:
//     { mfa_required: false, access_token: "...", token_type: "bearer" }
//     ⚠ No refresh cookie set here — MFA not yet wired into login flow.
//     ⚠ No user object — must call GET /auth/me separately.
//
//   POST /auth/mfa-verify response:
//     Sets httpOnly refresh cookie + returns { access_token, token_type }
//     Schema: { temp_token: str, totp_code: str }
//
//   POST /auth/refresh response:
//     { access_token: "...", token_type: "bearer" } + rotates cookie.
//
//   GET /auth/me response:
//     { id, username, email, role, client_id, force_password_change, ... }

const useAuthStore = create((set, get) => ({
  accessToken: null,
  user: null,
  isInitialized: false,
  isLoading: false,
  error: null,

  _setAccessToken: (token) => set({ accessToken: token }),
  _clearAuth: () => set({ accessToken: null, user: null }),

  // Called once on app mount. Tries to silently refresh the session using the
  // httpOnly refresh cookie. Sets isInitialized=true when done (success or fail)
  // so ProtectedRoute knows it can make auth decisions.
  bootstrap: async () => {
    try {
      const { data } = await api.post('/auth/refresh');
      const token = data.access_token;
      // Set token in store BEFORE calling /auth/me so the request interceptor
      // picks it up from getState() — no need for inline Authorization header.
      set({ accessToken: token });
      const { data: me } = await api.get('/auth/me');
      set({ user: me, isInitialized: true });
    } catch {
      // No valid refresh cookie — user is logged out. That is fine.
      set({ accessToken: null, user: null, isInitialized: true });
    }
  },

  login: async (username, password) => {
    set({ isLoading: true, error: null });
    try {
      const form = new URLSearchParams();
form.append('username', username);
form.append('password', password);
const { data } = await api.post('/auth/login', form, {
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
});

      // Backend key is mfa_required (not requires_mfa).
      // When MFA is required: backend returns { mfa_required: true, temp_token }
      // and does NOT set the refresh cookie yet — that happens after mfa-verify.
      if (data.mfa_required) {
        set({ isLoading: false });
        return { requires_mfa: true, temp_token: data.temp_token };
      }

      const token = data.access_token;
      // BUG FIXED: set token in store first; the request interceptor reads it
      // via getState() synchronously, so the following /auth/me call gets the
      // Authorization header automatically. Removed redundant inline header.
      set({ accessToken: token });

      const { data: me } = await api.get('/auth/me');
      set({ user: me, isLoading: false });

      if (me.force_password_change) return { force_password_change: true };
      return { done: true, role: me.role };

    } catch (err) {
      const msg = err.response?.data?.detail || 'Login failed. Check credentials.';
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  // Only called when MFA is triggered. Backend schema: { temp_token, totp_code }
  verifyMfa: async (temp_token, code) => {
    set({ isLoading: true, error: null });
    try {
      const { data } = await api.post('/auth/mfa-verify', {
        temp_token,
        totp_code: code,   // backend field is totp_code, not code
      });
      const token = data.access_token;
      // BUG FIXED: same as login — set token first, then fetch /auth/me via
      // interceptor. Removed redundant inline Authorization header.
      set({ accessToken: token });
      const { data: me } = await api.get('/auth/me');
      set({ user: me, isLoading: false });
      if (me.force_password_change) return { force_password_change: true };
      return { done: true, role: me.role };
    } catch (err) {
      const msg = err.response?.data?.detail || 'Invalid MFA code.';
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  forceChangePassword: async (new_password) => {
    set({ isLoading: true, error: null });
    try {
      await api.post('/auth/force-change-password', { new_password });
      // Re-fetch /auth/me to get updated force_password_change=false
      const { data: me } = await api.get('/auth/me');
      set({ user: { ...get().user, ...me }, isLoading: false });
      return { done: true };
    } catch (err) {
      const msg = err.response?.data?.detail || 'Password change failed.';
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  forgotPassword: async (email) => {
    set({ isLoading: true, error: null });
    try {
      await api.post('/auth/forgot-password', { email });
      set({ isLoading: false });
    } catch (err) {
      const msg = err.response?.data?.detail || 'Request failed.';
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  resetPassword: async (token, new_password) => {
    set({ isLoading: true, error: null });
    try {
      await api.post('/auth/reset-password', { token, new_password });
      set({ isLoading: false });
    } catch (err) {
      const msg = err.response?.data?.detail || 'Reset failed.';
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch {
      // Always clear client state even if server call fails
    } finally {
      set({ accessToken: null, user: null });
    }
  },

  clearError: () => set({ error: null }),
}));

// Wire the axios interceptor to this store.
// registerTokenGetter runs synchronously at module load, before any request is
// made, so the interceptor always reads the latest token via getState().
registerTokenGetter(() => useAuthStore.getState().accessToken);
registerAuthActions({
  setAccessToken: (token) => useAuthStore.getState()._setAccessToken(token),
  clearAuth:      ()      => useAuthStore.getState()._clearAuth(),
});

export default useAuthStore;
