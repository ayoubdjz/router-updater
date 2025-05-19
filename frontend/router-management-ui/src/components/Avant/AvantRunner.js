import React, { useState } from 'react';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { useAuth } from '../../contexts/AuthContext';
import { runAvantChecks, unlockRouter } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
import UpdateRunner from '../Update/UpdateRunner'; // We'll create this
import ApresRunner from '../Apres/ApresRunner'; // We'll create this

const AvantRunner = () => {
  const { credentials, sessionData, updateSessionData, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [avantResult, setAvantResult] = useState(null);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);

  const handleRunAvant = async () => {
    if (!credentials) {
      setError("Not authenticated. Please login.");
      return;
    }
    setIsLoading(true);
    setError('');
    setLogs([]);
    setAvantResult(null);

    try {
      const response = await runAvantChecks(credentials);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setAvantResult(response.data);
        updateSessionData({ // Save crucial data for subsequent steps
          ident_data: response.data.ident_data,
          lock_file_path: response.data.lock_file_path, // from ident_data.lock_file_path
          avant_file_path: response.data.avant_file_path,
          config_file_path: response.data.config_file_path,
          avantCompleted: true,
          updateCompleted: false, // Reset update status
          apresCompleted: false   // Reset apres status
        });
        setError(''); // Clear previous errors
      } else {
        setError(response.data.message || 'AVANT checks failed.');
        setAvantResult(null); // Clear previous successful result
        updateSessionData({ avantCompleted: false });
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during AVANT checks.';
      setError(errorMsg);
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...(err.response?.data?.logs || [])]);
      setAvantResult(null);
      updateSessionData({ avantCompleted: false });
      if(err.response?.status === 401 || err.response?.status === 403) { // Example: if API returns these for auth issues
          logout(); // Force logout if auth seems to be the problem
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnlock = async () => {
    if (!sessionData.lock_file_path) {
        setError("No lock file path found in session to unlock.");
        return;
    }
    setIsLoading(true);
    setError('');
    try {
        await unlockRouter(sessionData.lock_file_path);
        setLogs(prev => [...prev, `Attempted to unlock router with lock file: ${sessionData.lock_file_path}`]);
        updateSessionData({ lock_file_path: null, avantCompleted: false, updateCompleted: false, apresCompleted: false }); // Clear lock path and statuses
        setAvantResult(null); // Clear previous results
    } catch (err) {
        const errorMsg = err.response?.data?.message || err.message || 'Failed to unlock router.';
        setError(errorMsg);
        setLogs(prevLogs => [...prevLogs, `Error unlocking: ${errorMsg}`]);
    } finally {
        setIsLoading(false);
    }
  };


  return (
    <Box sx={{ my: 2, p: 2, border: '1px solid lightgray', borderRadius: 1 }}>
      <Typography variant="h5">1. Pre-Checks (AVANT)</Typography>
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <Button
        variant="contained"
        onClick={handleRunAvant}
        disabled={isLoading || sessionData.avantCompleted}
        sx={{ mr: 1, my:1 }}
      >
        {isLoading ? <CircularProgress size={24} /> : 'Run AVANT Checks'}
      </Button>
       {sessionData.lock_file_path && (
           <Button
            variant="outlined"
            color="warning"
            onClick={handleUnlock}
            disabled={isLoading}
            sx={{my:1}}
           >
             {isLoading ? <CircularProgress size={24} /> : 'Force Unlock Router & Reset'}
           </Button>
       )}

      <LogDisplay logs={logs} title="AVANT Execution Logs" />

      {avantResult && avantResult.status === 'success' && (
        <Box sx={{my:1}}>
          <Alert severity="success">AVANT checks completed successfully!</Alert>
          <Typography variant="body2" sx={{mt:1}}>
            AVANT File: {avantResult.avant_file_path}<br />
            Config File: {avantResult.config_file_path}<br />
            Lock File: {avantResult.lock_file_path}
          </Typography>
        </Box>
      )}

      {sessionData.avantCompleted && !sessionData.updateCompleted && (
        <UpdateRunner />
      )}
      {sessionData.avantCompleted && sessionData.updateCompleted && !sessionData.apresCompleted && (
         <ApresRunner />
      )}
       {sessionData.avantCompleted && !sessionData.updateCompleted && !sessionData.apresCompleted && ( // Option to run APRES if no UPDATE
        <ApresRunner allowSkipUpdate={true} />
      )}
    </Box>
  );
};

export default AvantRunner;