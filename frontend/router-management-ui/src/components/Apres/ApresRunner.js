import React, { useState } from 'react';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { useAuth } from '../../contexts/AuthContext';
import { runApresChecks } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
import Paper from '@mui/material/Paper';

const ApresRunner = ({ allowSkipUpdate = false }) => {
  const { credentials, sessionData, updateSessionData } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [apresResult, setApresResult] = useState(null);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);

  const handleRunApres = async () => {
    if (!credentials || !sessionData.ident_data) {
      setError("Authentication or AVANT session data missing.");
      return;
    }

    setIsLoading(true);
    setError('');
    setLogs([]);
    setApresResult(null);

    const apresPayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password,
    };

    try {
      const response = await runApresChecks(apresPayload);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setApresResult(response.data);
        updateSessionData({ 
            apresCompleted: true,
            lock_file_path: null, // Lock should be released by APRES API
            // ident_data: null // ident_data is consumed by APRES
        });
        setError('');
      } else {
        setError(response.data.message || 'APRES checks failed.');
        updateSessionData({ apresCompleted: false });
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during APRES checks.';
      setError(errorMsg);
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...(err.response?.data?.logs || [])]);
      updateSessionData({ apresCompleted: false });
    } finally {
      setIsLoading(false);
    }
  };

  // Conditions for rendering this component
  const shouldRenderDirectlyAfterAvant = allowSkipUpdate && sessionData.avantCompleted && !sessionData.updateCompleted;
  const shouldRenderAfterUpdate = sessionData.avantCompleted && sessionData.updateCompleted;

  if (!shouldRenderDirectlyAfterAvant && !shouldRenderAfterUpdate) {
    return null;
  }

  return (
    <Box sx={{ my: 2, p: 2, border: '1px solid lightgray', borderRadius: 1 }}>
      <Typography variant="h5">
        {sessionData.updateCompleted ? "3. Post-Checks & Comparison (APRES)" : "Run Post-Checks (APRES) - Skipping Update"}
      </Typography>
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <Button
        variant="contained"
        onClick={handleRunApres}
        disabled={isLoading || sessionData.apresCompleted}
        sx={{my:1}}
      >
        {isLoading ? <CircularProgress size={24} /> : 'Run APRES Checks'}
      </Button>

      <LogDisplay logs={logs} title="APRES Execution Logs" />

      {apresResult && apresResult.status === 'success' && (
        <Box sx={{my:1}}>
          <Alert severity="success">APRES checks and comparison completed successfully!</Alert>
          <Typography variant="body2" sx={{mt:1}}>
            APRES File: {apresResult.apres_file_path}<br />
            Comparison File: {apresResult.comparison_file_path}
          </Typography>
          {/* Displaying comparison_data can be complex. For now, just acknowledge. */}
          {apresResult.comparison_data && (
            <Paper elevation={1} sx={{p:1, mt:1, maxHeight: 300, overflow:'auto', backgroundColor: '#eee'}}>
              <Typography variant="subtitle2">Comparison Summary:</Typography>
              <pre style={{fontSize: '0.8em', whiteSpace: 'pre-wrap', wordBreak: 'break-all'}}>
                {/* Very basic rendering of comparison data. Needs proper formatting. */}
                {Object.entries(apresResult.comparison_data).map(([section, data]) => (
                    `${section}:\n  AVANT: ${data.removed?.join(', ') || 'N/A'}\n  APRÈS: ${data.added?.join(', ') || 'N/A'}\n\n`
                ))}
              </pre>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
};

export default ApresRunner;