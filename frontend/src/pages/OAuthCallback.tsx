import React from 'react';
import { Navigate } from 'react-router-dom';

const OAuthCallback: React.FC = () => {
  return <Navigate to="/dashboard" replace />;
};

export default OAuthCallback;