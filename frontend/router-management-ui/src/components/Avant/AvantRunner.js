import React, { useState, useEffect } from 'react';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import { toast } from 'react-toastify';
import { useMutation } from '@tanstack/react-query';

import { useAuth } from '../../contexts/AuthContext';
import { runAvantChecks, unlockRouter } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
import StructuredDataDisplay from '../Common/StructuredDataDisplay';

const AvantRunner = ({ runOnLoad = false, onAvantProcessComplete }) => { 
  const { credentials, sessionData, updateSession, resetWorkflow, logout } = useAuth();
  
  const [currentLogs, setCurrentLogs] = useState([]);
  const [currentError, setCurrentError] = useState(''); // For errors not directly from mutation object

  const avantMutation = useMutation({
    mutationFn: runAvantChecks, 
    onSuccess: (response) => {
      const data = response.data;
      setCurrentLogs(data.logs || []);
      updateSession({
        ident_data: data.ident_data,
        lock_file_path: data.lock_file_path,
        avant_file_path: data.avant_file_path,
        config_file_path: data.config_file_path,
        avantCompleted: true,
        avantData: data.structured_data,
        viewState: 'avant_success'
      });
      setCurrentError('');
      toast.success("AVANT pre-checks completed successfully!");
      if (onAvantProcessComplete) onAvantProcessComplete(true); 
    },
    onError: (error) => {
      const errorMsg = error.response?.data?.message || error.message || 'AVANT checks failed.';
      setCurrentError(errorMsg); // Set local error for display within this component
      toast.error(errorMsg);
      setCurrentLogs(error.response?.data?.logs || [errorMsg]);
      updateSession({ 
        avantCompleted: false, 
        viewState: 'avant_error',
        avantData: error.response?.data?.structured_data || null 
      });
      if (onAvantProcessComplete) onAvantProcessComplete(false); 
      if(error.response?.status === 401 || error.response?.status === 403) {
        logout(); 
      }
    },
  });

  const unlockMutation = useMutation({
    mutationFn: unlockRouter,
    onSuccess: (response) => {
        const data = response.data;
        setCurrentLogs(prev => [...prev, `Force Unlock: ${data.message}`, ...(data.logs || [])]);
        toast.info(data.message || "Unlock attempt successful.");
        resetWorkflow(); 
        if (onAvantProcessComplete) onAvantProcessComplete(false); // Signal reset
    },
    onError: (error) => {
        const errorMsg = error.response?.data?.message || error.message || 'Failed to force unlock router.';
        setCurrentError(errorMsg); // Use local error state
        toast.error(errorMsg);
        setCurrentLogs(prevLogs => [...prevLogs, `Error during force unlock: ${errorMsg}`]);
    }
  });

  useEffect(() => {
    if (runOnLoad && credentials && !sessionData.avantCompleted && !avantMutation.isPending && !avantMutation.isSuccess ) {
      updateSession({ 
        ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
        avantCompleted: false, avantData: null, updateAttempted: false, updateCompleted: false,
        apresCompleted: false, apresData: null, comparisonResults: null, viewState: 'avant_loading'
      });
      setCurrentLogs([]); 
      setCurrentError(''); 
      avantMutation.mutate(credentials);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runOnLoad, credentials, sessionData.avantCompleted]); // Removed avantMutation from deps to avoid loop, check isPending/isSuccess instead


  const handleManualRunAvant = () => {
    if (!credentials) {
      setCurrentError("Not authenticated. Please login.");
      toast.error("Not authenticated.");
      return;
    }
    updateSession({ // Reset all workflow progress for a full re-run
        ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
        avantCompleted: false, avantData: null, updateAttempted: false, updateCompleted: false,
        apresCompleted: false, apresData: null, comparisonResults: null, viewState: 'avant_loading'
    });
    setCurrentLogs([]);
    setCurrentError('');
    avantMutation.mutate(credentials);
  };

  const handleForceUnlockAndReset = () => {
    if (!sessionData.lock_file_path) {
        toast.warn("No lock file known for unlock operation.");
        setCurrentError("No lock file path found to unlock.");
        return;
    }
    setCurrentError(''); 
    unlockMutation.mutate(sessionData.lock_file_path);
  };

  // Display loading state if this component triggered the AVANT run
  if (avantMutation.isPending) {
    return (
      <Paper elevation={3} sx={{ p: 3, textAlign: 'center', my: 2 }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 2 }}>Running AVANT Pre-Checks...</Typography>
        <Typography variant="body2">Please wait, this may take a few moments.</Typography>
        <Box sx={{width: '90%', margin: '20px auto', textAlign: 'left'}}>
            <LogDisplay logs={currentLogs} title="AVANT Execution Logs (In Progress)" />
        </Box>
      </Paper>
    );
  }
  

  return (
    <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: '#f3e5f5' }}>
      <Box sx={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1}}>
        <Typography variant="h5">AVANT Pre-Check Section</Typography>
        <Box>
            {!avantMutation.isPending && ( // Show re-run only if not currently running
                <Button variant="outlined" onClick={handleManualRunAvant} disabled={unlockMutation.isPending}>
                    {sessionData.avantCompleted ? "Re-run AVANT Checks" : "Run AVANT Checks"}
                </Button>
            )}
            {sessionData.lock_file_path && (
                <Button variant="outlined" color="warning" onClick={handleForceUnlockAndReset}
                    disabled={avantMutation.isPending || unlockMutation.isPending} sx={{ml:1}}>
                    {unlockMutation.isPending ? <CircularProgress size={20}/> : "Force Unlock & Reset"}
                </Button>
            )}
        </Box>
      </Box>
      
      {/* Display error from avantMutation or local currentError */}
      {(currentError || avantMutation.isError) && (
        <Alert severity="error" sx={{my:1}}>
            {currentError || avantMutation.error?.response?.data?.message || avantMutation.error?.message}
        </Alert>
      )}

      <LogDisplay logs={currentLogs} title="AVANT Execution Logs" />

      {sessionData.avantCompleted && sessionData.avantData && (
        <Box sx={{my:2}}>
          <Alert severity="success" icon={false} sx={{mb:1}}>AVANT pre-checks completed successfully!</Alert>
          <StructuredDataDisplay data={sessionData.avantData} titlePrefix="AVANT" />
          <Typography variant="caption" display="block" gutterBottom sx={{mt:2, color:'text.secondary'}}>
              AVANT File: {sessionData.avant_file_path || "N/A"}<br />
              Config File: {sessionData.config_file_path || "N/A"}<br />
              Lock File: {sessionData.lock_file_path || "N/A"}
          </Typography>
        </Box>
      )}
      {!sessionData.avantCompleted && !avantMutation.isPending && !avantMutation.isError && (
        <Alert severity="info">AVANT checks have not completed successfully or have not been run for this session.</Alert>
      )}
    </Paper>
  );
};

export default AvantRunner;