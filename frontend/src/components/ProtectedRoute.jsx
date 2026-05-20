import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import useAuthStore from '../store/authStore';

export default function ProtectedRoute({ children, allowedRoles = [] }) {
  const { user, accessToken, isInitialized } = useAuthStore();
  const location = useLocation(); 

  // Hold route evaluation if the app bootstrap hook is actively executing its refresh handshake
  if (!isInitialized) {
    return (
      <div style={{
        background: '#0a0b0d',
        minHeight: '100vh'
      }} />
    ); 
  }

  // If credentials are completely absent post-handshake, bounce to login.
  // Passes the current sub-route path context down into location state memory fields
  if (!user || !accessToken) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Scope matching enforcement boundary checks
  if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
    const fallbackPath = user.role === 'client' ? '/client/events' : '/analyst/dashboard';
    return <Navigate to={fallbackPath} replace />;
  }

  // Active child tree context is fully preserved across browser reloads
  return children;
}