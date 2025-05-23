import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { testConnection } from '../api/routerApi';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { toast } from 'react-toastify';
import { useMutation } from '@tanstack/react-query'; // Correct import

const LoginPage = () => {
  const [ip, setIp] = useState(localStorage.getItem('lastIp') || '');
  const [username, setUsername] = useState(localStorage.getItem('lastUsername') || '');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
  const auth = useAuth();

  const testConnectionMutation = useMutation({
    mutationFn: testConnection,
    onSuccess: (data, variables) => {
      auth.login(variables); 
      toast.info("Login successful! Initializing pre-checks (AVANT)...");
      navigate('/dashboard', { state: { runAvantOnLoad: true } });
    },
    onError: (error) => {
      const errorMsg = error.response?.data?.message || error.message || 'Login failed.';
      toast.error(`Login Failed: ${errorMsg}`);
      auth.logout();
    },
  });

  const handleSubmit = async (event) => {
    event.preventDefault();
    localStorage.setItem('lastIp', ip);
    localStorage.setItem('lastUsername', username);
    testConnectionMutation.mutate({ ip, username, password });
  };

  return (
    <Container component="main" maxWidth="xs">
      <Paper elevation={3} sx={{ marginTop: 8, padding: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Typography component="h1" variant="h5">
          Router Login
        </Typography>
        {testConnectionMutation.isError && (
          <Alert severity="error" sx={{ width: '100%', mt: 2 }}>
            {testConnectionMutation.error.response?.data?.message || testConnectionMutation.error.message}
          </Alert>
        )}
        
        <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1, width: '100%' }}>
          <TextField fullWidth margin="normal" label="Router IP Address" value={ip} onChange={(e) => setIp(e.target.value)} disabled={testConnectionMutation.isPending} required autoFocus/>
          <TextField fullWidth margin="normal" label="Username" value={username} onChange={(e) => setUsername(e.target.value)} disabled={testConnectionMutation.isPending} required autoComplete="username"/>
          <TextField fullWidth margin="normal" label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={testConnectionMutation.isPending} required autoComplete="current-password"/>
          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
            disabled={testConnectionMutation.isPending}
          >
            {testConnectionMutation.isPending ? <CircularProgress size={24} color="inherit" /> : 'Login'}
          </Button>
        </Box>
      </Paper>
    </Container>
  );
};

export default LoginPage;