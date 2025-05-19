import React, { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext(null);

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
    return data ? JSON.parse(data) : {}; // Store ident_data, lock_file_path etc.
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
    if (Object.keys(sessionData).length > 0) {
      localStorage.setItem('sessionData', JSON.stringify(sessionData));
    } else {
      localStorage.removeItem('sessionData');
    }
  }, [sessionData]);


  const login = (creds) => {
    setCredentials(creds);
    setIsAuthenticated(true);
  };

  const logout = () => {
    setCredentials(null);
    setIsAuthenticated(false);
    setSessionData({}); // Clear session data on logout
    localStorage.removeItem('credentials');
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('sessionData');
  };

  // Function to update session data, e.g., after AVANT run
  const updateSessionData = (newData) => {
    setSessionData(prevData => ({ ...prevData, ...newData }));
  };


  return (
    <AuthContext.Provider value={{ isAuthenticated, credentials, sessionData, login, logout, updateSessionData }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);