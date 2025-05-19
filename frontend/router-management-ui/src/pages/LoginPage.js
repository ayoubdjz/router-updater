import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { testConnection, runAvantChecks } from '../api/routerApi'; // Added runAvantChecks
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import LinearProgress from '@mui/material/LinearProgress'; // For combined loading

const LoginPage = () => {
  const [ip, setIp] = useState(localStorage.getItem('lastIp') || ''); // Remember last IP
  const [username, setUsername] = useState(localStorage.getItem('lastUsername') || ''); // Remember last username
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState('');
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
      setLoadingMessage('Testing connection...');
      await testConnection(creds);
      auth.login(creds); // Set credentials and isAuthenticated

      setLoadingMessage('Running pre-checks (AVANT)... This may take a moment.');
      // Now immediately run AVANT checks
      const avantResponse = await runAvantChecks(creds); // Pass fresh creds

      if (avantResponse.data.status === 'success') {
        auth.updateSession({ // Store all relevant AVANT data in session
          ident_data: avantResponse.data.ident_data,
          lock_file_path: avantResponse.data.lock_file_path,
          avant_file_path: avantResponse.data.avant_file_path,
          config_file_path: avantResponse.data.config_file_path,
          avantCompleted: true,
          avantData: avantResponse.data.structured_data,
          // Reset other workflow flags
          updateAttempted: false,
          updateCompleted: false,
          apresCompleted: false,
        });
        navigate('/dashboard');
      } else {
        setError(`AVANT checks failed: ${avantResponse.data.message || 'Unknown AVANT error'}`);
        auth.logout(); // Logout if AVANT fails immediately after login
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'Operation failed. Please try again.';
      setError(errorMsg);
      console.error('Login/AVANT error:', err.response || err);
      auth.logout(); // Ensure logout on any failure during this initial sequence
    } finally {
      setIsLoading(false);
      setLoadingMessage('');
    }
  };

  return (
    <Container component="main" maxWidth="xs">
      <Paper elevation={3} sx={{ marginTop: 8, padding: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5">
          Router Login & Initialisation
        </Typography>
        {isLoading && <Box sx={{ width: '100%', my: 2 }}><LinearProgress /><Typography variant="caption" display="block" textAlign="center">{loadingMessage}</Typography></Box>}
        {error && !isLoading && <Alert severity="error" sx={{ width: '100%', mt: 2 }}>{error}</Alert>}
        
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
            {isLoading ? <CircularProgress size={24} color="inherit" /> : 'Login & Run Pre-Checks'}
          </Button>
        </Box>
      </Paper>
    </Container>
  );
};

export default LoginPage;