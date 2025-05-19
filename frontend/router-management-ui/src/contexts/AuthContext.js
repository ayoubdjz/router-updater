import React, { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext(null);

const initialSessionData = {
  ident_data: null,
  lock_file_path: null,
  avant_file_path: null,
  config_file_path: null,
  avantCompleted: false,
  avantData: null, // To store structured AVANT results
  updateAttempted: false, // To know if user chose to update or skip
  updateCompleted: false,
  updateData: null, // To store any structured data from update
  apresCompleted: false,
  apresData: null, // To store structured APRES results
  comparisonResults: null, // To store comparison
};

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('isAuthenticated') === 'true';
  });
  const [credentials, setCredentials] = useState(() => {
    const creds = localStorage.getItem('credentials');
    return creds ? JSON.parse(creds) : null;
  });
  const [sessionData, setSessionData] = useState(() => {
    const data = localStorage.getItem('sessionData');
    return data ? JSON.parse(data) : { ...initialSessionData };
  });

  useEffect(() => {
    localStorage.setItem('isAuthenticated', isAuthenticated);
    if (credentials) {
      localStorage.setItem('credentials', JSON.stringify(credentials));
    } else {
      localStorage.removeItem('credentials');
    }
  }, [isAuthenticated, credentials]);

  useEffect(() => {
    localStorage.setItem('sessionData', JSON.stringify(sessionData));
  }, [sessionData]);

  const login = (creds) => {
    setCredentials(creds);
    setIsAuthenticated(true);
    setSessionData({ ...initialSessionData }); // Reset session data on new login
  };

  const logout = () => {
    setCredentials(null);
    setIsAuthenticated(false);
    setSessionData({ ...initialSessionData }); // Clear all session data
    localStorage.removeItem('credentials');
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('sessionData');
  };

  const updateSession = (newData) => {
    setSessionData(prevData => ({ ...prevData, ...newData }));
  };
  
  const resetWorkflow = () => {
    // Keeps credentials and auth status, but resets workflow progress
    setSessionData(prev => ({
        ...initialSessionData,
        // Potentially keep lock_file_path if a manual unlock is intended next
        // For a full reset, clear it:
        // lock_file_path: null 
    }));
  };


  return (
    <AuthContext.Provider value={{ isAuthenticated, credentials, sessionData, login, logout, updateSession, resetWorkflow }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);