import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid'; 
import Divider from '@mui/material/Divider';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { toast } from 'react-toastify';

import UpdateRunner from '../components/Update/UpdateRunner';
import ApresRunner from '../components/Apres/ApresRunner';
import ConfirmationModal from '../components/Common/ConfirmationModal';
import StructuredDataDisplay from '../components/Common/StructuredDataDisplay';
import LogDisplay from '../components/Common/LogDisplay';
import ComparisonModal from '../components/Common/ComparisonModal';
import { useAuth } from '../contexts/AuthContext';
import { runAvantChecks, unlockRouter } from '../api/routerApi';
import LogModal from '../components/Common/LogModal';
import UpdateModal from '../components/Update/UpdateModal';

const DashboardPage = () => {
  const { sessionData, updateSession, resetWorkflow, credentials, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const [isAvantLoading, setIsAvantLoading] = useState(false);
  const [avantError, setAvantError] = useState('');
  const [avantLogs, setAvantLogs] = useState([]);

  const [isActionLoading, setIsActionLoading] = useState(false);
  const [actionError, setActionError] = useState(''); 
  const [dashboardActionLogs, setDashboardActionLogs] = useState([]);  const [showApresConfirmModal, setShowApresConfirmModal] = useState(false);
  const [showComparisonDetailModal, setShowComparisonDetailModal] = useState(false);
  const [showAvantLogsModal, setShowAvantLogsModal] = useState(false);
  const [showUpdateModal, setShowUpdateModal] = useState(false);

  useEffect(() => {
    // If we have credentials but AVANT hasn't been run, trigger it
    if (credentials && !sessionData.avantCompleted && !isAvantLoading) { 
      navigate(location.pathname, { state: { ...location.state, runAvantOnLoad: false }, replace: true }); 
      const performInitialAvantChecks = async () => {
        setIsAvantLoading(true); setAvantError(''); setAvantLogs([]);
        updateSession({ 
          ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
          avantCompleted: false, avantData: null, updateAttempted: false, updateCompleted: false,
          apresCompleted: false, apresData: null, comparisonResults: null, viewState: 'avant_loading'
        });
        try {
          const response = await runAvantChecks(credentials);
          setAvantLogs(response.data.logs || []);
          if (response.data.status === 'success') {
            updateSession({
              ident_data: response.data.ident_data, lock_file_path: response.data.lock_file_path,
              avant_file_path: response.data.avant_file_path, config_file_path: response.data.config_file_path,
              avantCompleted: true, avantData: response.data.structured_data, viewState: 'avant_success'
            });
            setAvantError(''); toast.success("AVANT pre-checks completed successfully!");
          } else {
            const errMsg = `AVANT checks failed: ${response.data.message || 'Unknown AVANT error'}`;
            setAvantError(errMsg); toast.error(errMsg);
            updateSession({ avantCompleted: false, viewState: 'avant_error' });
          }
        } catch (err) {
          const errorMsg = err.response?.data?.message || err.message || 'An error occurred during initial AVANT checks.';
          setAvantError(errorMsg); toast.error(errorMsg);
          const errLogs = err.response?.data?.logs || [];
          setAvantLogs(prevLogs => [...prevLogs, `Network/Request Error: ${errorMsg}`, ...errLogs]);
          updateSession({ avantCompleted: false, viewState: 'avant_error' });
          if(err.response?.status === 401 || err.response?.status === 403) {
            logout(); navigate('/login', { replace: true, state: { error: "Session issue during AVANT. Please login again." }});
          }
        } finally { setIsAvantLoading(false); }
      };
      performInitialAvantChecks();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps 
  }, [location.state, credentials, sessionData.avantCompleted, isAvantLoading]);
  const handleTriggerUpdate = () => {
    setShowUpdateModal(true);
  };

  const handleConfirmUpdate = (path) => {
    updateSession({ 
      updateAttempted: true, 
      updateCompleted: false, 
      viewState: 'update_config',
      updatePath: path 
    });
  };

  const handleTriggerApres = () => { 
    setShowApresConfirmModal(true);
  };
  const handleConfirmApres = () => {
    setShowApresConfirmModal(false);
    // Run APRES directly when user confirms
    updateSession({ viewState: 'apres_running' }); 
  };

  const handleCancelApres = () => {
    setShowApresConfirmModal(false);
  };

  const handleUpdateProcessFinished = (updateSuccess) => {
    // After update attempt, the "Run APRES" button in the APRES section will become more prominent or enabled.
    // User clicks it to run APRES. No automatic modal.
    updateSession({ viewState: 'update_finished_ready_for_apres' }); // New state to signify update done, APRES next
    if(updateSuccess) {
        toast.success("Software update process reported success. You can now run APRES checks.");
    } else {
        toast.warn("Software update process reported issues. Check logs. You can still attempt APRES checks.");
    }
  };
  
  // handleProceedWithApres and handleSkipApres are no longer needed

  const handleApresProcessFinished = (apresSuccess) => {
    updateSession({ viewState: 'workflow_complete' });
    // Toast for APRES success/failure is handled within ApresRunner
  };
  
  const handleForceUnlockAndFullReset = async () => { /* ... same as before ... */ 
    if (!sessionData.lock_file_path) {
        toast.warn("No lock file path known."); setActionError("No lock file path known."); return;
    }
    setIsActionLoading(true); setActionError(''); setDashboardActionLogs([]);
    try {
        const unlockResponse = await unlockRouter(sessionData.lock_file_path);
        const unlockMsg = `Force Unlock: ${unlockResponse.data.message || 'Unlock attempted.'}`;
        setDashboardActionLogs(prev => [...prev, unlockMsg, ...(unlockResponse.data.logs || [])]);
        toast.info(unlockMsg); resetWorkflow();
    } catch (err) {
        const errorMsg = err.response?.data?.message || err.message || 'Failed to force unlock router.';
        setActionError(errorMsg); toast.error(errorMsg);
        setDashboardActionLogs(prevLogs => [...prevLogs, `Error during force unlock: ${errorMsg}`]);
    } finally { setIsActionLoading(false); }
  };
  const showInitialAvantLoading = isAvantLoading || sessionData.viewState === 'avant_loading';
  const showInitialAvantError = avantError && !sessionData.avantCompleted && sessionData.viewState === 'avant_error';
  const showAvantNotRunMessage = !credentials || (!sessionData.avantCompleted && !isAvantLoading && !avantError);
  
  const showAvantResultsSection = sessionData.avantCompleted;
  const showUpdateConfigSection = sessionData.avantCompleted && sessionData.updateAttempted && !sessionData.updateCompleted && sessionData.viewState === 'update_config';
  const showApresRunner = sessionData.avantCompleted && sessionData.viewState === 'apres_running' && !sessionData.apresCompleted;
  const showApresResultsDisplay = sessionData.apresCompleted && sessionData.apresData;

  if (showInitialAvantLoading) { /* ... same loading display ... */ 
      return ( <Paper elevation={3} sx={{ p: 3, textAlign: 'center', mt: 4 }}> <CircularProgress size={60} /> <Typography variant="h6" sx={{ mt: 2 }}>Running AVANT...</Typography> <Box sx={{width: '80%', margin: '20px auto'}}> <LogDisplay logs={avantLogs} title="Initial AVANT Logs" /> </Box> </Paper> );
  }
  if (showInitialAvantError) { /* ... same error display ... */ 
      return ( <Paper elevation={3} sx={{ p: 3, mt: 4 }}> <Alert severity="error" sx={{mb:2}}> AVANT Failed: {avantError} </Alert> <LogDisplay logs={avantLogs} title="Initial AVANT Error Logs" /> <Button onClick={() => { logout(); navigate('/login', {replace: true}); }} variant="contained" sx={{mt:2}}>Login</Button> </Paper> );
  }  if (showAvantNotRunMessage) {
      return (
        <Paper elevation={3} sx={{p:3, textAlign:'center', mt:4}}>
          <Typography>Please wait while AVANT initializes...</Typography>
          <CircularProgress sx={{ mt: 2 }} />
        </Paper>
      );
  }
  
  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="h4" gutterBottom sx={{ textAlign: 'center', mb: 1 }}>Router Operations</Typography>
      <Typography variant="subtitle1" sx={{ textAlign: 'center', mb: 3 }}>
        Device: {sessionData.ident_data?.ip} (Hostname: {sessionData.ident_data?.router_hostname || 'N/A'})
      </Typography>

      {actionError && <Alert severity="error" sx={{my:2}}>{actionError}</Alert>}
      <LogDisplay logs={dashboardActionLogs} title="Dashboard Action Logs" />

      {/* --- AVANT Section --- */}
      {showAvantResultsSection && (
        <Paper elevation={2} sx={{ p: {xs:2, md:3}, mb: 3, backgroundColor: '#e3f2fd' /* Lighter purple */ }}>
          <Box sx={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap:1}}>
            <Typography variant="h5">AVANT Pre-Check Results</Typography>
            {!sessionData.apresCompleted && (
                <Button variant="contained" color="secondary" onClick={handleTriggerUpdate}
                    disabled={isActionLoading || !sessionData.avantCompleted}
                > Perform Software Update </Button>
            )}
          </Box>
          <StructuredDataDisplay data={sessionData.avantData} titlePrefix="AVANT" />          <Typography variant="caption" display="block" gutterBottom sx={{mt:2, color:'text.secondary'}}>
              AVANT File: {sessionData.avant_file_path || "N/A"} | Config File: {sessionData.config_file_path || "N/A"} | Lock File: {sessionData.lock_file_path || "N/A"}
          </Typography>
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <Button variant="outlined" onClick={() => setShowAvantLogsModal(true)}>
              Show AVANT Logs
            </Button>
          </Box>
        </Paper>
      )}
      
      {showUpdateConfigSection && (
        <>
          <Divider sx={{my:3}}><Chip label="Update Process Configuration" /></Divider>
          <UpdateRunner onUpdateProcessFinished={handleUpdateProcessFinished} />
        </>
      )}
      
      {sessionData.avantCompleted && <Divider sx={{my:3}}><Chip label="Post Operations" /></Divider> }

      {/* --- APRES Section --- */}
      {sessionData.avantCompleted && (
        <Paper elevation={2} sx={{ p: {xs:2, md:3}, mb: 3, backgroundColor: '#e3f2fd' /* Lighter blue */ }}>
          <Box sx={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb:2, flexWrap: 'wrap', gap:1}}>
            <Typography variant="h5">APRES Post-Check & Comparison</Typography>            {!sessionData.apresCompleted && !showApresRunner && (
                <Button variant="contained" color="primary" onClick={handleTriggerApres}
                    disabled={isActionLoading} 
                > Run Post-Checks </Button>
            )}
            {/* Show "Show Comparison" button if APRES completed and comparison results exist */}
            {sessionData.apresCompleted && sessionData.comparisonResults && Object.keys(sessionData.comparisonResults).length > 0 && (
                 <Button variant="outlined" onClick={() => setShowComparisonDetailModal(true)}>
                    Show AVANT vs APRES Comparison
                </Button>
            )}
          </Box>
            {showApresRunner && (
              <ApresRunner onApresProcessFinished={handleApresProcessFinished} />
          )}

          {showApresResultsDisplay && (
              <>
                <StructuredDataDisplay data={sessionData.apresData} titlePrefix="APRES" />
              </>
          )}
        </Paper>
      )}

      {sessionData.lock_file_path && (
           <Button variant="outlined" color="warning" onClick={handleForceUnlockAndFullReset}
            disabled={isActionLoading} sx={{my:2, display:'block', mx:'auto'}}           > Force Unlock Router </Button>
       )}      
      <ComparisonModal 
        open={showComparisonDetailModal} 
        onClose={() => setShowComparisonDetailModal(false)}
        comparisonResults={sessionData.comparisonResults}
      />

      <LogModal
        open={showAvantLogsModal}
        onClose={() => setShowAvantLogsModal(false)}
        logs={avantLogs}
        title="AVANT Execution Logs"
      />      <ConfirmationModal
        open={showApresConfirmModal}
        onClose={handleCancelApres}
        title="Run APRES Without Update?"
        message="Would you like to run the APRES post-checks without performing a software update? This will compare the current router state with the initial AVANT checks."
        confirmText="Run APRES"
        cancelText="Cancel"
        onConfirm={handleConfirmApres}
      />

      <UpdateModal
        open={showUpdateModal}
        onClose={() => setShowUpdateModal(false)}
        onConfirm={handleConfirmUpdate}
      />
    </Box>
  );
};

export default DashboardPage;