import React, { useEffect } from 'react';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import Navbar from './components/Common/Navbar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import FilesPage from './pages/FilesPage';
import { useAuth } from './contexts/AuthContext';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';

import { ToastContainer } from 'react-toastify'; // <<<--- ADDED
import 'react-toastify/dist/ReactToastify.css'; // <<<--- ADDED (import CSS for react-toastify)


const ProtectedRoute = () => {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />; 
};

function App() {
  const { isAuthenticated, logout, sessionData } = useAuth();

  useEffect(() => {
    const routerName = sessionData?.ident_data?.router_hostname || sessionData?.ident_data?.model || 'juniper';
    document.title = `Router Management - ${routerName}`;
  }, [sessionData?.ident_data?.router_hostname, sessionData?.ident_data?.model]);

  return (
    <>
      <ToastContainer // <<<--- ADDED ToastContainer here
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="colored" // Or "light", "dark"
      />
      <Navbar isAuthenticated={isAuthenticated} onLogout={logout} />
      <Container maxWidth="lg" sx={{ mt: 2, pb: 4 /* Add padding bottom */ }}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/files" element={<FilesPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} /> 
          </Route>
          
          {!isAuthenticated && <Route path="/" element={<Navigate to="/login" replace />} />} 
          <Route path="*" element={<Typography variant="h3" align="center" sx={{mt:5}}>404 Not Found</Typography>} />
        </Routes>
      </Container>
    </>
  );
}

export default App;