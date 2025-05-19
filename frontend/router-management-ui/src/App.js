import React from 'react';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import Navbar from './components/Common/Navbar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import FilesPage from './pages/FilesPage';
import { useAuth } from './contexts/AuthContext';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography'; // <<<--- ADD THIS IMPORT

// ProtectedRoute component
const ProtectedRoute = () => {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />; // Renders child routes if authenticated
};

function App() {
  const { isAuthenticated, logout } = useAuth();

  return (
    <>
      <Navbar isAuthenticated={isAuthenticated} onLogout={logout} />
      <Container maxWidth="lg" sx={{ mt: 2 }}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          
          <Route element={<ProtectedRoute />}> {/* Wrap protected routes */}
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/files" element={<FilesPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} /> {/* Default to dashboard if logged in */}
          </Route>
          
          {/* Fallback for non-authenticated users trying to access root */}
          {!isAuthenticated && <Route path="/" element={<Navigate to="/login" replace />} />} 
          {/* You can add a 404 page here */}
          <Route path="*" element={<Typography variant="h3" align="center" sx={{mt:5}}>404 Not Found</Typography>} />

        </Routes>
      </Container>
    </>
  );
}

export default App;