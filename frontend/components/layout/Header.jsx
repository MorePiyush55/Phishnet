import React from 'react';
import useAuth from '../../hooks/useAuth';

export default function Header() {
  const { user, logout } = useAuth() || {};

  return (
    <header style={{display: 'flex', justifyContent: 'space-between', padding: '12px 24px', background: '#f7f7f7'}}>
      <div>PhishNet</div>
      <div>
        {user ? (
          <>
            <span style={{marginRight: 12}}>{user.name}</span>
            <button onClick={logout}>Logout</button>
          </>
        ) : (
          <a href="/login">Login</a>
        )}
      </div>
    </header>
  );
}
