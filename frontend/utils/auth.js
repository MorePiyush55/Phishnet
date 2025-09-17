import axios from 'axios';

const BACKEND = process.env.NEXT_PUBLIC_BACKEND_URL || '';

export function storeTokens({ accessToken, refreshToken }) {
  if (typeof window === 'undefined') return;
  localStorage.setItem('phishnet_access_token', accessToken || '');
  localStorage.setItem('phishnet_refresh_token', refreshToken || '');
}

export function getStoredUser() {
  if (typeof window === 'undefined') return null;
  const userRaw = localStorage.getItem('phishnet_user');
  return userRaw ? JSON.parse(userRaw) : null;
}

export function clearTokens() {
  if (typeof window === 'undefined') return;
  localStorage.removeItem('phishnet_access_token');
  localStorage.removeItem('phishnet_refresh_token');
  localStorage.removeItem('phishnet_user');
}

export function setStoredUser(user) {
  if (typeof window === 'undefined') return;
  localStorage.setItem('phishnet_user', JSON.stringify(user));
}

export const api = axios.create({
  baseURL: BACKEND,
  withCredentials: true
});

export async function fetchWithRetry(url, options = {}, retries = 3, backoff = 300) {
  let attempt = 0;
  while (true) {
    try {
      const resp = await fetch(url, options);
      if (!resp.ok && attempt < retries) {
        attempt += 1;
        await new Promise(r => setTimeout(r, backoff * Math.pow(2, attempt - 1)));
        continue;
      }
      return resp;
    } catch (e) {
      attempt += 1;
      if (attempt > retries) throw e;
      await new Promise(r => setTimeout(r, backoff * Math.pow(2, attempt - 1)));
    }
  }
}
