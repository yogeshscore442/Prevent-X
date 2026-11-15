import axios from 'axios';
import { formatErrorMessage } from '@/utils/formatError';

export const api = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper to extract cookie value
export function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

// Request interceptor: inject token, tenant header, and CSRF token
api.interceptors.request.use(
  (config) => {
    // 1. Bearer token fallback if present
    const token = localStorage.getItem('preventx_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // 2. Active Tenant Organization Scope
    const activeOrgId = localStorage.getItem('preventx_active_org_id');
    if (activeOrgId) {
      config.headers['X-Organization-Id'] = activeOrgId;
    }

    // 3. Double-submit CSRF token for mutating requests
    const csrfToken = getCookie('preventx_csrf_token');
    if (csrfToken && ['post', 'put', 'patch', 'delete'].includes(config.method?.toLowerCase() || '')) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: handles session expirations & normalizes error messages
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !window.location.pathname.includes('/login')) {
      localStorage.removeItem('preventx_token');
      localStorage.removeItem('preventx_user');
      window.location.href = '/login';
    }

    // Normalize error payloads so err.response.data.detail is ALWAYS a string
    if (error.response?.data) {
      if (typeof error.response.data.detail === 'object' && error.response.data.detail !== null) {
        error.response.data.detail = formatErrorMessage(error.response.data.detail);
      }
      error.message = formatErrorMessage(error.response.data);
    }

    return Promise.reject(error);
  }
);


