import React, { useState, useEffect } from 'react';
// import Button from '@mui/material/Button'; // Not used directly for action anymore
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import { toast } from 'react-toastify';
import { useAuth } from '../../contexts/AuthContext';
import { runApresChecks } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
import StructuredDataDisplay from '../Common/StructuredDataDisplay';

const ApresRunner = ({ onApresProcessFinished }) => { 
  const { credentials, sessionData, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);
  const [apresData, setApresData] = useState(null);
  const [comparisonResults, setComparisonResults] = useState(null);

  const handleRunApres = async () => {
    if (!credentials || !sessionData.ident_data) {
      const msg = "Authentication or AVANT session data missing for APRES.";
      setError(msg); toast.error(msg); 
      if (onApresProcessFinished) onApresProcessFinished(false, null, null, msg); // Notify parent of critical failure
      return;
    }

    setIsLoading(true); setError(''); setLogs([]);
    toast.info("Running APRES checks and comparison...");

    const apresPayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password,
    };

    let apresSuccess = false;
    let finalApresData = null;
    let finalComparisonResults = null;
    let criticalErrorForCallback = null; 

    try {
      const response = await runApresChecks(apresPayload);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        finalApresData = response.data.structured_data_apres;
        finalComparisonResults = response.data.comparison_results;
        setApresData(finalApresData); // Save for display
        setComparisonResults(finalComparisonResults);
        setError('');
        apresSuccess = true;
        toast.success("APRES checks and comparison completed successfully!");
      } else {
        const errMsg = response.data.message || 'APRES checks failed.';
        setError(errMsg); toast.error(`APRES Failed: ${errMsg}`);
        criticalErrorForCallback = errMsg; 
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during APRES checks.';
      setError(errorMsg); toast.error(`APRES Error: ${errorMsg}`);
      criticalErrorForCallback = errorMsg;
      const errLogs = err.response?.data?.logs || [];
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
      if(err.response?.status === 401 || err.response?.status === 403) logout();
    } finally {
      setIsLoading(false);
      if (onApresProcessFinished) {
        onApresProcessFinished(apresSuccess, finalApresData, finalComparisonResults, criticalErrorForCallback);
      }
    }
  };
    
  useEffect(() => {
    if (sessionData.avantCompleted && sessionData.viewState === 'apres_running' && !sessionData.apresCompleted && !isLoading) {
      // Added !isLoading to prevent re-triggering if already running due to rapid state changes.
      handleRunApres();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionData.avantCompleted, sessionData.viewState, sessionData.apresCompleted]); // isLoading removed from deps to avoid loop if handleRunApres sets it

  if (!(sessionData.avantCompleted && sessionData.viewState === 'apres_running' && !sessionData.apresCompleted)) {
    return null; 
  }

  // Loading state (like AvantRunner)
  if (isLoading) {
    return (
      <Paper elevation={3} sx={{ p: 3, textAlign: 'center', my: 2 }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 2 }}>Running APRES Post-Checks...</Typography>
        <Typography variant="body2">Please wait, this may take a few moments.</Typography>
        <Box sx={{width: '90%', margin: '20px auto', textAlign: 'left'}}>
            <LogDisplay logs={logs} title="APRES Execution Logs (In Progress)" />
        </Box>
      </Paper>
    );
  }

  // Error state
  if (error) {
    return (
      <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: '#ffebee' }}>
        <Alert severity="error" sx={{my:1}}>{error}</Alert>
        <LogDisplay logs={logs} title="APRES Execution Logs" />
      </Paper>
    );
  }

  // Success state (optional, if you want to show results here)
  if (apresData) {
    return (
      <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: '#e3f2fd' }}>
        <Alert severity="success" icon={false} sx={{mb:1}}>APRES post-checks completed successfully!</Alert>
        <StructuredDataDisplay data={apresData} titlePrefix="APRES" />
        <LogDisplay logs={logs} title="APRES Execution Logs" />
      </Paper>
    );
  }

  // Info state if nothing is running
  return (
    <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: '#f3e5f5' }}>
      <Typography variant="body2">APRES checks have not started yet for this session.</Typography>
    </Paper>
  );
};

export default ApresRunner;