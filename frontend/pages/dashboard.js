import React from 'react';
import useAuth from '../hooks/useAuth';

export default function Dashboard() {
  const { user } = useAuth() || {};

  if (!user) return <div>Please log in</div>;

  return (
    <div>
      <h1>Welcome, {user.name}</h1>
      <p>{user.email}</p>
    </div>
  );
}
