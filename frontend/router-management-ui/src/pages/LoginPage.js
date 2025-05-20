import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { testConnection } from '../api/routerApi'; // runAvantChecks removed from here
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { toast } from 'react-toastify'; 

const LoginPage = () => {
  const [ip, setIp] = useState(localStorage.getItem('lastIp') || '');
  const [username, setUsername] = useState(localStorage.getItem('lastUsername') || '');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const auth = useAuth();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setIsLoading(true);
    setError('');
    
    localStorage.setItem('lastIp', ip);
    localStorage.setItem('lastUsername', username);

    const creds = { ip, username, password };

    try {
      await testConnection(creds);
      auth.login(creds); 
      
      // Navigate immediately. DashboardPage will handle AVANT run.
      // No toast here about starting AVANT, DashboardPage will provide feedback.
      navigate('/dashboard', { state: { runAvantOnLoad: true } });

    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'Login failed. Please check credentials and router connectivity.';
      setError(errorMsg);
      toast.error(`Login Failed: ${errorMsg}`); 
      console.error('Login error:', err.response || err);
      auth.logout(); 
      setIsLoading(false);
    }
  };

  return (
    // ... (rest of the JSX is the same as the previous version)
    <Container component="main" maxWidth="xs">
      <Paper elevation={3} sx={{ marginTop: 8, padding: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5">
          Router Login
        </Typography>
        {error && <Alert severity="error" sx={{ width: '100%', mt: 2 }}>{error}</Alert>}
        
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1, width: '100%' }}>
          <TextField
            margin="normal"
            required
            fullWidth
            id="ip"
            label="Router IP Address"
            name="ip"
            autoComplete="off"
            autoFocus
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            disabled={isLoading}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            id="username"
            label="Username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={isLoading}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            name="password"
            label="Password"
            type="password"
            id="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={isLoading}
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
            disabled={isLoading}
          >
            {isLoading ? <CircularProgress size={24} color="inherit" /> : 'Login'}
          </Button>
        </Box>
      </Paper>
    </Container>
  );
};

export default LoginPage;