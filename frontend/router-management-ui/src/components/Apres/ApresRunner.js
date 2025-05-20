import React, { useState } from 'react';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import { toast } from 'react-toastify';
import { useAuth } from '../../contexts/AuthContext';
import { runApresChecks } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
// StructuredDataDisplay is now used by DashboardPage for APRES results, not directly here after run.

const ApresRunner = ({ onApresProcessFinished }) => { 
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);
  // No local state for apresRunData or comparisonData for display, relies on sessionData for parent re-render

  const handleRunApres = async () => {
    if (!credentials || !sessionData.ident_data) {
      const msg = "Authentication or AVANT session data missing for APRES.";
      setError(msg); toast.error(msg); return;
    }

    setIsLoading(true); setError(''); setLogs([]);
    toast.info("Running APRES checks and comparison...");

    const apresPayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password,
    };

    let apresSuccess = false;
    try {
      const response = await runApresChecks(apresPayload);
      setLogs(response.data.logs || []);

      if (response.data.status === 'success') {
        updateSession({ 
          apresCompleted: true, 
          apresData: response.data.structured_data_apres,
          comparisonResults: response.data.comparison_results, 
          lock_file_path: null, // Lock released by API
          // viewState: 'workflow_complete' // Dashboard will set this based on callback
        });
        // Store file paths locally if needed for a quick link, though Dashboard can also get them
        // setApresFile(response.data.apres_file_path); 
        // setComparisonFile(response.data.comparison_file_path);
        setError('');
        apresSuccess = true;
        toast.success("APRES checks and comparison completed successfully!");
      } else {
        const errMsg = response.data.message || 'APRES checks failed.';
        setError(errMsg); toast.error(`APRES Failed: ${errMsg}`);
        updateSession({ apresCompleted: false }); 
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during APRES checks.';
      setError(errorMsg); toast.error(`APRES Error: ${errorMsg}`);
      const errLogs = err.response?.data?.logs || [];
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
      updateSession({ apresCompleted: false });
      if(err.response?.status === 401 || err.response?.status === 403) logout();
    } finally {
      setIsLoading(false);
      if (onApresProcessFinished) onApresProcessFinished(apresSuccess);
    }
  };
  
  // This component is now primarily for the *action* of running APRES.
  // Display of results happens in DashboardPage based on sessionData.
  // It's visible when DashboardPage sets sessionData.viewState to 'apres_running'
  if (!(sessionData.avantCompleted && sessionData.viewState === 'apres_running' && !sessionData.apresCompleted)) {
    return null; 
  }
  
  return (
    // The Paper and Title are now part of DashboardPage's APRES section
    // This component focuses on the button and logs during its execution
    <Box sx={{ my: 2, p: 2, border: '1px dashed #ccc', borderRadius: 1, backgroundColor: isLoading ? '#f0f0f0' : 'transparent' }}>
      <Typography variant="h6" gutterBottom>Processing APRES...</Typography>
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <Button
        variant="contained"
        color="info" // Changed color for distinction
        onClick={handleRunApres}
        disabled={isLoading || sessionData.apresCompleted} 
        sx={{my:1}}
      >
        {isLoading ? <CircularProgress size={24} color="inherit" /> : 'Confirm & Run APRES Now'}
      </Button>
      <LogDisplay logs={logs} title="Live APRES Execution Logs" />
    </Box>
  );
};

export default ApresRunner;