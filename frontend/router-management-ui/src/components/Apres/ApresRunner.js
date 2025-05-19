import React, { useState } from 'react';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Grid from '@mui/material/Grid'; // For side-by-side
import { useAuth } from '../../contexts/AuthContext';
import { runApresChecks } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
import StructuredDataDisplay from '../Common/StructuredDataDisplay';

const ApresRunner = ({ onApresProcessFinished, allowSkipUpdate = false }) => { // Renamed prop
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);
  const [apresRunData, setApresRunData] = useState(null);
  const [showComparisonModal, setShowComparisonModal] = useState(false);

  const handleRunApres = async () => {
    // ... (validation - same as before)
    if (!credentials || !sessionData.ident_data) {
      setError("Authentication or AVANT session data missing. Cannot run APRES.");
      return;
    }

    setIsLoading(true);
    setError('');
    setLogs([]);
    setApresRunData(null);
    // updateSession({ apresCompleted: false, apresData: null, comparisonResults: null }); // Reset specific flags

    const apresPayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password,
    };

    let apresSuccess = false;
    try {
      const response = await runApresChecks(apresPayload);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setApresRunData(response.data);
        updateSession({ 
          apresCompleted: true, 
          apresData: response.data.structured_data_apres,
          comparisonResults: response.data.comparison_results,
          lock_file_path: null 
        });
        setError('');
        apresSuccess = true;
      } else {
        setError(response.data.message || 'APRES checks failed.');
        updateSession({ apresCompleted: false });
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during APRES checks.';
      setError(errorMsg);
      const errLogs = err.response?.data?.logs || [];
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
      updateSession({ apresCompleted: false });
      if(err.response?.status === 401 || err.response?.status === 403) {
        logout();
      }
    } finally {
      setIsLoading(false);
      if (onApresProcessFinished) onApresProcessFinished(apresSuccess);
    }
  };
  
  // Determine if this component should be rendered based on workflow state from DashboardPage
  // This component is now more directly controlled by DashboardPage's viewState or similar logic
  // The 'allowSkipUpdate' helps differentiate the title/context.
  const shouldRun = sessionData.avantCompleted && !sessionData.apresCompleted && sessionData.viewState === 'apres_running';

  if (!shouldRun) {
    return null;
  }
  
  const title = (sessionData.updateAttempted && sessionData.updateCompleted) ? 
                "Step 3: Post-Checks & Comparison (APRES)" : 
                "Run Post-Checks & Comparison (APRES)";

  return (
    <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: '#e3f2fd' /* Light blue for final step */ }}>
      <Typography variant="h5" gutterBottom>{title}</Typography>
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <Button
        variant="contained"
        onClick={handleRunApres}
        disabled={isLoading || sessionData.apresCompleted}
        sx={{my:1}}
      >
        {isLoading ? <CircularProgress size={24} sx={{color: 'white'}} /> : 'Run APRES & Compare'}
      </Button>

      <LogDisplay logs={logs} title="APRES Execution Logs (bottom of section)" />

      {sessionData.apresCompleted && apresRunData?.status === 'success' && (
        <Box sx={{my:2}}>
          <Alert severity="success" icon={false}>APRES checks and comparison completed successfully!</Alert>
          <Typography variant="caption" display="block" gutterBottom sx={{mt:1}}>
            APRES File: {apresRunData.apres_file_path}<br />
            Comparison Report File (JSON): {apresRunData.comparison_file_path}
          </Typography>
          {sessionData.apresData && (
            <StructuredDataDisplay data={sessionData.apresData} />
          )}
          {sessionData.comparisonResults && Object.keys(sessionData.comparisonResults).length > 0 && (
            <Button variant="outlined" sx={{mt:2}} onClick={() => setShowComparisonModal(true)}>
              View Detailed Comparison
            </Button>
          )}
        </Box>
      )}

      {sessionData.comparisonResults && (
        <Dialog open={showComparisonModal} onClose={() => setShowComparisonModal(false)} maxWidth="xl" fullWidth>
          <DialogTitle>AVANT vs APRES Comparison Details</DialogTitle>
          <DialogContent>
            {Object.values(sessionData.comparisonResults).map((diff, index) => (
              <Accordion key={diff.section_title + index} defaultExpanded={diff.status !== "Identique"} sx={{mb:1.5}} TransitionProps={{ unmountOnExit: true }}>
                <AccordionSummary 
                    expandIcon={<ExpandMoreIcon />}
                    sx={{ 
                        backgroundColor: diff.status === "Identique" ? 'rgba(0,0,0,0.03)' : 
                                         (diff.status === "Modifié" ? '#fff3e0' : // Orange-ish for Modified
                                         (diff.status === "Nouveau" ? '#e8f5e9' : // Green-ish for New
                                         (diff.status === "Supprimé" ? '#ffebee' : // Red-ish for Removed
                                         'inherit' )))
                    }}
                >
                  <Typography sx={{ fontWeight: 'medium', flexShrink: 0, width: '40%' }}>
                    {diff.section_title}
                  </Typography>
                  <Typography sx={{ color: 'text.secondary', fontWeight: diff.status !== "Identique" ? 'bold': 'normal' }}>
                    Status: {diff.status}
                  </Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ backgroundColor: '#fafafa', borderTop: '1px solid rgba(0,0,0,0.1)' }}>
                    {diff.status !== "Identique" ? (
                        <Grid container spacing={2}>
                            <Grid item xs={12} md={6}>
                                <Typography variant="subtitle1" color="textSecondary" gutterBottom>AVANT</Typography>
                                {diff.lines_removed && diff.lines_removed.length > 0 && diff.lines_removed[0] !== "✓ (Identique)" && diff.lines_removed[0] !== "✓ (Aucun retrait ou contenu identique)" ? (
                                <Paper component="pre" variant="outlined" sx={{p:1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 300, overflowY: 'auto', fontSize:'0.75rem', fontFamily:'monospace', backgroundColor: '#fff', borderColor: diff.status === "Supprimé" || diff.status === "Modifié" ? "error.light" : "transparent" }}>
                                    {diff.lines_removed.join('\n')}
                                </Paper>
                                ) : <Typography variant="body2" sx={{pl:1.5}}><i>{diff.lines_removed && diff.lines_removed.length > 0 ? diff.lines_removed[0] : "N/A or unchanged"}</i></Typography>}
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <Typography variant="subtitle1" color="textSecondary" gutterBottom>APRÈS</Typography>
                                {diff.lines_added && diff.lines_added.length > 0 && diff.lines_added[0] !== "✓ (Identique)" && diff.lines_added[0] !== "✓ (Aucun ajout ou contenu identique)" ? (
                                <Paper component="pre" variant="outlined" sx={{p:1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 300, overflowY: 'auto', fontSize:'0.75rem', fontFamily:'monospace', backgroundColor: '#fff', borderColor: diff.status === "Nouveau" || diff.status === "Modifié" ? "success.light" : "transparent"}}>
                                    {diff.lines_added.join('\n')}
                                </Paper>
                                ) : <Typography variant="body2" sx={{pl:1.5}}><i>{diff.lines_added && diff.lines_added.length > 0 ? diff.lines_added[0] : "N/A or unchanged"}</i></Typography>}
                            </Grid>
                        </Grid>
                    ) : (
                        <Typography variant="body2" sx={{p:1.5}}>Contents are identical after normalization.</Typography>
                    )}
                </AccordionDetails>
              </Accordion>
            ))}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setShowComparisonModal(false)}>Close</Button>
          </DialogActions>
        </Dialog>
      )}
    </Paper>
  );
};

export default ApresRunner;