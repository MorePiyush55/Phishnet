import React, { createContext, useState, useEffect } from 'react';
import { getStoredUser, storeTokens, clearTokens } from '../utils/auth';

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(getStoredUser());
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // could verify token on load
  }, []);

  const login = (userData, tokens) => {
    storeTokens(tokens);
    setUser(userData);
  };

  const logout = () => {
    clearTokens();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
