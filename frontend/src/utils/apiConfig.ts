/**
 * Centralized API base URL configuration for CertifyAI.
 * - In local development (`npm run dev`): connects to http://127.0.0.1:8000
 * - In production on Vercel (Unified single project): uses relative path '' (same domain /api/...)
 * - If custom VITE_API_URL is provided: uses that explicit URL.
 */
const rawUrl =
  import.meta.env.VITE_API_URL !== undefined && import.meta.env.VITE_API_URL !== ''
    ? import.meta.env.VITE_API_URL
    : import.meta.env.DEV
    ? 'http://127.0.0.1:8000'
    : '';

export const BACKEND_URL = String(rawUrl).replace(/\/+$/, '');

