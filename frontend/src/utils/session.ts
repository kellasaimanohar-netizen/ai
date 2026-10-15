/**
 * Where the sign-in is kept. "Keep me signed in" uses localStorage, so it survives closing the browser;
 * otherwise sessionStorage, so it ends with the tab. The server's token lifetime matches (7 days or 12 hours).
 */
const TOKEN_KEY = 'certifyai_admin_token';
const USER_KEY = 'certifyai_admin_user';

const stores = (): Storage[] => {
  const out: Storage[] = [];
  try { out.push(localStorage); } catch { /* storage blocked */ }
  try { out.push(sessionStorage); } catch { /* storage blocked */ }
  return out;
};

const read = (key: string): string | null => {
  for (const s of stores()) {
    const v = s.getItem(key);
    if (v) return v;
  }
  return null;
};

export const getStoredToken = (): string | null => read(TOKEN_KEY);

export function getStoredUser<T = any>(): T | null {
  const raw = read(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function saveSession(user: unknown, token: string, remember: boolean): void {
  clearSession();
  try {
    const target = remember ? localStorage : sessionStorage;
    target.setItem(USER_KEY, JSON.stringify(user));
    target.setItem(TOKEN_KEY, token);
  } catch { /* storage blocked: the session lasts until the page reloads */ }
}

/** Updates the stored copy of the user (after a profile change) wherever the session is kept. */
export function updateStoredUser(changes: Record<string, unknown>): void {
  for (const s of stores()) {
    const raw = s.getItem(USER_KEY);
    if (!raw) continue;
    try {
      s.setItem(USER_KEY, JSON.stringify({ ...JSON.parse(raw), ...changes }));
    } catch { /* the stored copy is only a cache */ }
  }
}

/** Swaps in a new token (after a password change) in whichever store holds the session. */
export function replaceToken(token: string): void {
  for (const s of stores()) {
    if (s.getItem(TOKEN_KEY)) s.setItem(TOKEN_KEY, token);
  }
}

export function clearSession(): void {
  for (const s of stores()) {
    s.removeItem(TOKEN_KEY);
    s.removeItem(USER_KEY);
  }
}
