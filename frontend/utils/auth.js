import axios from 'axios';

const BACKEND = process.env.NEXT_PUBLIC_BACKEND_URL || '';

export function storeTokens({ accessToken, refreshToken }) {
  if (typeof window === 'undefined') return;
  
  // Store tokens with multiple key formats for backward compatibility
  localStorage.setItem('phishnet_access_token', accessToken || '');
  localStorage.setItem('phishnet_refresh_token', refreshToken || '');
  
  // Also store with the 'token' key used by many components
  localStorage.setItem('token', accessToken || '');
  localStorage.setItem('access_token', accessToken || '');
}

export function getStoredUser() {
  if (typeof window === 'undefined') return null;
  const userRaw = localStorage.getItem('phishnet_user');
  return userRaw ? JSON.parse(userRaw) : null;
}

export function clearTokens() {
  if (typeof window === 'undefined') return;
  
  // Clear all token variations
  localStorage.removeItem('phishnet_access_token');
  localStorage.removeItem('phishnet_refresh_token');
  localStorage.removeItem('phishnet_user');
  localStorage.removeItem('token');
  localStorage.removeItem('access_token');
}

export function setStoredUser(user) {
  if (typeof window === 'undefined') return;
  localStorage.setItem('phishnet_user', JSON.stringify(user));
}

export const api = axios.create({
  baseURL: BACKEND,
  withCredentials: true
});

// Add request interceptor to include auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token') || localStorage.getItem('phishnet_access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor to handle token expiration
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Clear expired tokens and redirect to login
      clearTokens();
      
      // If we're not already on login page, redirect there
      if (typeof window !== 'undefined' && !window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);

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
