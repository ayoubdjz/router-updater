import React, { useState, useEffect } from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';

import UpdateRunner from '../components/Update/UpdateRunner';
import ApresRunner from '../components/Apres/ApresRunner';
import ConfirmationModal from '../components/Common/ConfirmationModal';
import StructuredDataDisplay from '../components/Common/StructuredDataDisplay';
import LogDisplay from '../components/Common/LogDisplay'; // Import LogDisplay
import { useAuth } from '../contexts/AuthContext';
import { unlockRouter } from '../api/routerApi'; // For manual unlock

const DashboardPage = () => {
  const { sessionData, updateSession, resetWorkflow, credentials } = useAuth();
  const [isLoading, setIsLoading] = useState(false); // General loading for dashboard actions
  const [error, setError] = useState(''); // General errors for dashboard actions
  const [dashboardLogs, setDashboardLogs] = useState([]); // Logs for actions like unlock

  // Modal states for APRES decision after UPDATE or when skipping UPDATE
  const [showApresConfirmModal, setShowApresConfirmModal] = useState(false);
  const [apresTriggerSource, setApresTriggerSource] = useState(''); // 'after_update' or 'skip_update'

  useEffect(() => {
    // This effect can trigger the APRES confirmation modal if conditions are met
    // e.g., if update just completed or user explicitly chose to skip update.
    if (sessionData.avantCompleted && sessionData.updateAttempted && !sessionData.apresCompleted) {
        // If update is done (success or fail), or if update was skipped, show APRES modal
        // This logic is now more directly handled by button clicks.
    }
  }, [sessionData.updateCompleted, sessionData.updateAttempted, sessionData.apresCompleted]);


  const handleTriggerUpdate = () => {
    updateSession({ updateAttempted: true, viewState: 'update_config' }); // Signal intent to update
  };

  const handleTriggerApresNoUpdate = () => {
    setApresTriggerSource('skip_update');
    setShowApresConfirmModal(true);
  };

  const handleUpdateProcessFinished = (updateSuccess) => { // Called by UpdateRunner
    // Update is done (either success or fail), now prompt for APRES
    setApresTriggerSource('after_update');
    setShowApresConfirmModal(true);
    // No need to change viewState here, ApresRunner visibility is conditional
  };
  
  const handleProceedWithApres = () => {
    setShowApresConfirmModal(false);
    updateSession({ viewState: 'apres_running' }); // ApresRunner will become visible
  };

  const handleSkipApres = () => {
    setShowApresConfirmModal(false);
    updateSession({ viewState: 'workflow_ended_no_apres', apresCompleted: true }); // Mark APRES as "done" (by skipping)
  };

  const handleApresProcessFinished = (apresSuccess) => { // Called by ApresRunner
    updateSession({ viewState: 'workflow_complete' });
  };
  
  const handleForceUnlockAndFullReset = async () => {
    if (!sessionData.lock_file_path) {
        setError("No lock file path known. Workflow might be already reset or AVANT didn't complete fully.");
        return;
    }
    setIsLoading(true);
    setError('');
    setDashboardLogs([]);
    try {
        const unlockResponse = await unlockRouter(sessionData.lock_file_path);
        setDashboardLogs(prev => [...prev, `Force Unlock: ${unlockResponse.data.message}`, ...(unlockResponse.data.logs || [])]);
        resetWorkflow(); // Full reset
    } catch (err) {
        const errorMsg = err.response?.data?.message || err.message || 'Failed to force unlock router.';
        setError(errorMsg);
        setDashboardLogs(prevLogs => [...prevLogs, `Error during force unlock: ${errorMsg}`]);
    } finally {
        setIsLoading(false);
    }
  };


  if (!sessionData.avantCompleted && !credentials) { // Should be caught by protected route, but as fallback
    return <Typography>Redirecting to login...</Typography>;
  }
  if (!sessionData.avantCompleted && credentials) { // AVANT is running (or failed) via LoginPage
      return (
          <Paper elevation={3} sx={{ p: 3, textAlign: 'center' }}>
              <CircularProgress />
              <Typography sx={{ mt: 2 }}>Initial pre-checks (AVANT) in progress or encountered an issue...</Typography>
              <Typography variant="caption" sx={{display:'block', mt:1}}>If this persists, please try logging out and in again.</Typography>
          </Paper>
      );
  }
  
  // AVANT is completed
  const showUpdateSection = sessionData.avantCompleted && sessionData.updateAttempted && !sessionData.updateCompleted;
  const showApresSection = sessionData.avantCompleted && 
                           ( (sessionData.updateAttempted && sessionData.viewState === 'apres_running') || // After update attempt (success/fail) and user chose APRES
                             (!sessionData.updateAttempted && sessionData.viewState === 'apres_running')    // Skipping update and user chose APRES
                           ) && 
                           !sessionData.apresCompleted;

  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="h4" gutterBottom sx={{ textAlign: 'center', mb: 1 }}>
        Router Operations Dashboard
      </Typography>
      <Typography variant="subtitle1" sx={{ textAlign: 'center', mb: 3 }}>
        Device: {sessionData.ident_data?.ip} (Hostname: {sessionData.ident_data?.router_hostname || 'N/A'})
      </Typography>

      {error && <Alert severity="error" sx={{my:2}}>{error}</Alert>}
      <LogDisplay logs={dashboardLogs} title="Dashboard Action Logs" />


      {/* AVANT Data Display Section */}
      <Paper elevation={2} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom>AVANT Pre-Check Results</Typography>
        {sessionData.avantData ? (
          <StructuredDataDisplay data={sessionData.avantData} />
        ) : (
          <Alert severity="warning">AVANT data not available.</Alert>
        )}
         <Typography variant="caption" display="block" gutterBottom sx={{mt:1}}>
            AVANT File: {sessionData.avant_file_path || "N/A"}<br />
            Config File: {sessionData.config_file_path || "N/A"}<br />
            Lock File in use: {sessionData.lock_file_path || "N/A (Workflow might be complete or reset)"}
        </Typography>
        {/* AVANT Logs are usually shown by AvantRunner, but if LoginPage runs it, they might be in sessionData.avantData.logs if API was changed to include them */}
        {sessionData.avantData?.logs && <LogDisplay logs={sessionData.avantData.logs} title="AVANT Execution Logs (from initial run)" />}
      </Paper>
      
      <Divider sx={{my:3}} />

      {/* Action Buttons Area - only if workflow is not fully completed */}
      {!sessionData.apresCompleted && sessionData.avantCompleted && (
        <Paper elevation={2} sx={{p:3, mb:3}}>
            <Typography variant="h5" gutterBottom>Next Steps</Typography>
            <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                    <Button
                        fullWidth
                        variant="contained"
                        color="secondary"
                        onClick={handleTriggerUpdate}
                        disabled={isLoading || sessionData.updateAttempted || !sessionData.avantCompleted}
                    >
                        Perform Software Update
                    </Button>
                </Grid>
                <Grid item xs={12} md={6}>
                    <Button
                        fullWidth
                        variant="contained"
                        color="primary"
                        onClick={handleTriggerApresNoUpdate}
                        disabled={isLoading || !sessionData.avantCompleted || sessionData.updateAttempted } // Disable if update was already chosen
                    >
                        Run Post-Checks & Comparison (No Update)
                    </Button>
                </Grid>
            </Grid>
        </Paper>
      )}
      
      {sessionData.lock_file_path && ( // Show manual unlock if lock file is known
           <Button
            variant="outlined"
            color="warning"
            onClick={handleForceUnlockAndFullReset}
            disabled={isLoading}
            sx={{my:2, display:'block', mx:'auto'}}
           >
             Force Unlock Router & Reset Full Workflow
           </Button>
       )}


      {/* Conditional Rendering of Update and Apres Runners */}
      {showUpdateSection && (
        <UpdateRunner onUpdateComplete={handleUpdateProcessFinished} />
      )}
      
      {showApresSection && (
        <ApresRunner onApresComplete={handleApresProcessFinished} allowSkipUpdate={!sessionData.updateCompleted && sessionData.updateAttempted} />
      )}


      {/* Confirmation Modals */}
      <ConfirmationModal
        open={showApresConfirmModal}
        title="Run APRES Checks?"
        message={
          apresTriggerSource === 'after_update' ?
          "The software update process has been attempted. Do you want to proceed with APRES (post-checks and comparison)?" :
          "You've chosen to skip the software update. Do you want to run APRES (post-checks and comparison) now?"
        }
        onConfirm={handleProceedWithApres}
        onCancel={handleSkipApres}
        confirmText="Yes, Run APRES"
        cancelText="No, Finish"
      />
      
      {sessionData.apresCompleted && (
          <Alert severity="success" sx={{mt:3}}>Workflow concluded. APRES checks are complete.</Alert>
      )}

    </Box>
  );
};

export default DashboardPage;