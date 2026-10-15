import { BACKEND_URL } from './apiConfig';
import { clearSession, getStoredToken } from './session';

export function getAuthToken(): string | null {
  return getStoredToken();
}

export function getAuthHeaders(additionalHeaders?: Record<string, string>): Record<string, string> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    ...(additionalHeaders || {})
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export async function apiFetch(endpoint: string, options: RequestInit = {}): Promise<Response> {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const url = endpoint.startsWith('http')
    ? endpoint
    : `${BACKEND_URL}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers
  });

  if (response.status === 401) {
    // Token expired or unauthorized
    console.warn('Session expired or unauthorized (401). Clearing credentials.');
    clearSession();
    if (window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
  }

  return response;
}
