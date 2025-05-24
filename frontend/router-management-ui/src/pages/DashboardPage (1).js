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
import IconButton from '@mui/material/IconButton';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ApresRunner from '../components/Apres/ApresRunner';
import ConfirmationModal from '../components/Common/ConfirmationModal';
import StructuredDataDisplay from '../components/Common/StructuredDataDisplay';
import LogDisplay from '../components/Common/LogDisplay';
import ComparisonModal from '../components/Common/ComparisonModal';
import { useAuth } from '../contexts/AuthContext';
import { runAvantChecks, runUpdateProcedure, runApresChecks, unlockRouter, listGeneratedFiles, getFileContent, deleteGeneratedFile } from '../api/routerApi';
import LogModal from '../components/Common/LogModal';
import UpdateModal from '../components/Update/UpdateModal';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';

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
  const [avantFileAction, setAvantFileAction] = useState({ loading: false, type: null });

  const [generatedFiles, setGeneratedFiles] = useState([]);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [fileAction, setFileAction] = useState({ type: null, filename: null });
  const [fileViewer, setFileViewer] = useState({ open: false, content: '', filename: '' });

  const [isUpdateLoading, setIsUpdateLoading] = useState(false);
  const [updateLogs, setUpdateLogs] = useState([]);
  const [updateResult, setUpdateResult] = useState(null);

  // Add a state to track which operation failed for retry
  const [lastFailedAction, setLastFailedAction] = useState(null); // e.g. { type: 'avant' | 'update' | 'apres', params: {...} }
  const [avantCriticalError, setAvantCriticalError] = useState(null); // For AVANT critical error
  const [apresCriticalError, setApresCriticalError] = useState(null); // For APRES critical error

  useEffect(() => {
    // Prevent polling if a critical error occurred
    if (avantCriticalError) return;
    // If we have credentials but AVANT hasn't been run, trigger it
    if (credentials && !sessionData.avantCompleted && !isAvantLoading && !avantCriticalError) { 
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
              ident_data: response.data.ident_data, lock_file_path: response.data.ident_data.lock_file_path,
              avant_file_path: response.data.avant_file_path, config_file_path: response.data.config_file_path,
              avantCompleted: true, avantData: response.data.structured_data, viewState: 'avant_success'
            });
            setAvantError(''); toast.success("Pre-checks completed successfully!");
          } else {
            setAvantCriticalError('A critical error occurred during pre-checks.');
            const errMsg = `AVANT checks failed: ${response.data.message || 'Unknown AVANT error'}`;
            setAvantError(errMsg); toast.error('An error occurred. Please retry.');
            updateSession({ avantCompleted: false, viewState: 'avant_error' });
          }
        } catch (err) {
          setAvantCriticalError('A critical error occurred during pre-checks.');
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
  }, [location.state, credentials, sessionData.avantCompleted, isAvantLoading, avantCriticalError]);
  const handleTriggerUpdate = () => {
    setShowUpdateModal(true);
  };

  const handleConfirmUpdate = async (filename) => {
    setShowUpdateModal(false);
    setIsUpdateLoading(true);
    setUpdateLogs([]);
    setUpdateResult(null);
    setActionError('');
    setDashboardActionLogs([]);
    try {
      if (!sessionData.ident_data || !credentials?.password) {
        setActionError('Missing credentials or session data.');
        setIsUpdateLoading(false);
        setLastFailedAction({ type: 'update', params: { filename } });
        toast.error('An error occurred. Please retry.');
        return;
      }
      setUpdateLogs([`Starting update with file: ${filename}`]);
      const response = await runUpdateProcedure({
        ident_data: sessionData.ident_data,
        password: credentials.password,
        image_file: filename
      });
      setUpdateLogs(response.data.logs || []);
      setUpdateResult(response.data);
      if (response.data.status === 'success') {
        toast.success('Update completed successfully!');
        updateSession({ updateCompleted: true, viewState: 'update_finished_ready_for_apres' });
        setLastFailedAction(null);
      } else {
        setActionError('An error occurred during update.');
        setLastFailedAction({ type: 'update', params: { filename } });
        toast.error('An error occurred. Please retry.');
        updateSession({ updateCompleted: false, viewState: 'update_finished_ready_for_apres' });
      }
    } catch (err) {
      setActionError('An error occurred during update.');
      setLastFailedAction({ type: 'update', params: { filename } });
      toast.error('An error occurred. Please retry.');
      updateSession({ updateCompleted: false, viewState: 'update_finished_ready_for_apres' });
    } finally {
      setIsUpdateLoading(false);
    }
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

  // Move this useEffect to the top level, before any early returns
  useEffect(() => {
    if (showAvantResultsSection) fetchGeneratedFiles();
  }, [showAvantResultsSection]);

  if (showInitialAvantLoading) { /* ... same loading display ... */ 
      return ( <Paper elevation={3} sx={{ p: 3, textAlign: 'center', mt: 4 }}> <CircularProgress size={60} /> <Typography variant="h6" sx={{ mt: 2 }}>Running Pre-Checks</Typography> <Box sx={{width: '80%', margin: '20px auto'}}> <LogDisplay logs={avantLogs} title="Initial AVANT Logs" /> </Box> </Paper> );
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
  
  // --- AVANT Reload Handler ---
  const handleReloadAvant = async () => {
    setIsAvantLoading(true); setAvantError(''); setAvantLogs([]); setAvantCriticalError(null);
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
        setAvantError(''); setAvantCriticalError(null);
      } else {
        setAvantCriticalError('A critical error occurred during pre-checks.');
        setAvantError('');
      }
    } catch (err) {
      setAvantCriticalError('A critical error occurred during pre-checks.');
      setAvantError('');
    } finally { setIsAvantLoading(false); }
  };

  // --- APRES Reload Handler ---
  const handleReloadApres = () => {
    setApresCriticalError(null);
    updateSession({ viewState: 'apres_running', apresCompleted: false });
  };

  // Handler to view AVANT file
  const handleViewAvantFile = () => {
    if (!sessionData.avant_file_path) return;
    setAvantFileAction({ loading: true, type: 'view' });
    const fileName = sessionData.avant_file_path.split(/[/\\]/).pop();
    window.open(`/api/files/${encodeURIComponent(fileName)}`, '_blank');
    setTimeout(() => setAvantFileAction({ loading: false, type: null }), 500); // quick reset
  };

  // Handler to delete AVANT file
  const handleDeleteAvantFile = async () => {
    if (!sessionData.avant_file_path) return;
    if (!window.confirm('Delete this AVANT file?')) return;
    setAvantFileAction({ loading: true, type: 'delete' });
    try {
      const fileName = sessionData.avant_file_path.split(/[/\\]/).pop();
      const res = await fetch(`/api/files/${encodeURIComponent(fileName)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        toast.success(data.message || 'AVANT file deleted.');
        updateSession({ avant_file_path: null, avantData: null });
      } else {
        toast.error(data.message || 'Failed to delete AVANT file.');
      }
    } catch (err) {
      toast.error('Error deleting AVANT file.');
    } finally {
      setAvantFileAction({ loading: false, type: null });
    }
  };

  // Fetch generated files list
  const fetchGeneratedFiles = async () => {
    setIsLoadingFiles(true);
    try {
      const res = await listGeneratedFiles();
      setGeneratedFiles(res.data.files || []);
    } catch (err) {
      toast.error('Failed to fetch generated files.');
    } finally {
      setIsLoadingFiles(false);
    }
  };

  // FileManager-style handlers
  const handleViewFile = async (filename) => {
    setFileAction({ type: 'view', filename });
    try {
      const res = await getFileContent(filename);
      setFileViewer({ open: true, content: res.data, filename });
    } catch (err) {
      toast.error(`Failed to fetch content for ${filename}: ${err.response?.data?.message || err.message}`);
    } finally {
      setFileAction({ type: null, filename: null });
    }
  };

  const handleDeleteFile = async (filename) => {
    if (!window.confirm(`Delete file ${filename}?`)) return;
    setFileAction({ type: 'delete', filename });
    try {
      const res = await deleteGeneratedFile(filename);
      toast.success(res.data.message || `File ${filename} deleted.`);
      setGeneratedFiles((prev) => prev.filter((f) => f !== filename));
      // If AVANT file deleted, update session
      if (filename === sessionData.avant_file_path?.split(/[/\\]/).pop()) {
        updateSession({ avant_file_path: null, avantData: null });
      }
      if (filename === sessionData.config_file_path?.split(/[/\\]/).pop()) {
        updateSession({ config_file_path: null });
      }
      if (filename === sessionData.lock_file_path?.split(/[/\\]/).pop()) {
        updateSession({ lock_file_path: null });
      }
    } catch (err) {
      toast.error(err.response?.data?.message || `Failed to delete ${filename}.`);
    } finally {
      setFileAction({ type: null, filename: null });
    }
  };

  const handleCloseFileViewer = () => {
    setFileViewer({ open: false, content: '', filename: '' });
  };

  const handleRetry = async () => {
    if (!lastFailedAction) return;
    if (lastFailedAction.type === 'avant') {
      await handleReloadAvant();
    } else if (lastFailedAction.type === 'update') {
      await handleConfirmUpdate(lastFailedAction.params.filename);
    } else if (lastFailedAction.type === 'apres') {
      await handleTriggerApres();
    }
  };

  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="h4" gutterBottom sx={{ textAlign: 'center', mb: 1 }}>Router Operations</Typography>
      <Typography variant="subtitle1" sx={{ textAlign: 'center', mb: 3 }}>
        Device: {sessionData.ident_data?.ip} (Hostname: {sessionData.ident_data?.router_hostname || 'N/A'})
      </Typography>

      {actionError && <Alert severity="error" sx={{my:2}}>{actionError}</Alert>}
      <LogDisplay logs={dashboardActionLogs} title="Dashboard Action Logs" />      {/* --- Software Update Button (Always visible) --- */}
      {showAvantResultsSection && (
        <Button 
          variant="contained" 
          color="primary"
          size="large"
          onClick={handleTriggerUpdate}
          disabled={isActionLoading || !sessionData.avantCompleted}
          sx={{ 
            display: 'block', 
            mx: 'auto', 
            mb: 3, 
            py: 1.5,
            px: 4,
            fontSize: '1.1rem',
            boxShadow: 3
          }}
        >
          Perform Software Update
        </Button>
      )}

      {/* --- AVANT Section --- */}
      {/* Three states: loading, error, success */}
      {showInitialAvantLoading && (
        <Paper elevation={3} sx={{ p: 3, textAlign: 'center', mt: 4 }}>
          <CircularProgress size={60} />
          <Typography variant="h6" sx={{ mt: 2 }}>Running Pre-Checks</Typography>
          <Box sx={{width: '80%', margin: '20px auto'}}>
            <LogDisplay logs={avantLogs} title="Initial AVANT Logs" />
          </Box>
        </Paper>
      )}
      {avantCriticalError && (
        <Box sx={{ width: '100%' }}>
          <Paper elevation={2} sx={{ p: 3, mb: 3, backgroundColor: '#fff3e0', textAlign: 'center' }}>
            <Alert severity="error" sx={{ mb: 2 }}>{avantCriticalError}</Alert>
            <Button variant="contained" color="primary" onClick={handleReloadAvant}>Reload Pre-Checks</Button>
          </Paper>
          <Button variant="contained" color="primary" size="large" disabled sx={{ display: 'block', mx: 'auto', mb: 3, py: 1.5, px: 4, fontSize: '1.1rem', boxShadow: 3 }}>
            Perform Software Update
          </Button>
          <Button variant="contained" color="primary" size="large" disabled sx={{ display: 'block', mx: 'auto', mb: 3, py: 1.5, px: 4, fontSize: '1.1rem', boxShadow: 3 }}>
            Run Post-Checks
          </Button>
        </Box>
      )}
      {showAvantResultsSection && !avantCriticalError && (
        <Paper elevation={2} sx={{ p: {xs:2, md:3}, mb: 3, backgroundColor: '#e3f2fd' }}>
          <Box sx={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap:1}}>
            <Typography variant="h5">Pre-Check Informations</Typography>
            <Button variant="outlined" color="secondary" onClick={handleReloadAvant} disabled={isAvantLoading} sx={{ml:2}}>
              {isAvantLoading ? <CircularProgress size={20} sx={{mr:1}} /> : null} Reload
            </Button>
          </Box>
          <StructuredDataDisplay data={sessionData.avantData} titlePrefix="AVANT" />
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <Button variant="outlined" onClick={() => setShowAvantLogsModal(true)}>
              Show AVANT Logs
            </Button>
          </Box>
          <Divider sx={{my:3}}><Typography variant="subtitle1" sx={{fontWeight:700, letterSpacing:1, color:'#1976d2', px:1}}>Generated Files (View)</Typography></Divider>
          <Box>
            {isLoadingFiles ? <CircularProgress sx={{ display: 'block', margin: 'auto', my:2 }} /> :
              generatedFiles.length === 0 ? (
                <Typography sx={{fontStyle:'italic'}}>No files found in generated_files directory.</Typography>
              ) : (
                <Grid container spacing={2}>
                  {generatedFiles.map((file) => (
                    <Grid item xs={12} md={6} lg={4} key={file}>
                      <Paper elevation={1} sx={{p:2, display:'flex', alignItems:'center', justifyContent:'space-between', mb:1}}>
                        <Box>
                          <Typography variant="subtitle2" sx={{fontWeight:600}}>{file}</Typography>
                        </Box>
                        <Box sx={{display:'flex', gap:1}}>
                          <IconButton 
                            edge="end" aria-label="view" 
                            onClick={() => handleViewFile(file)}
                            disabled={fileAction.type && fileAction.filename !== file}
                          >
                            {fileAction.type === 'view' && fileAction.filename === file ? <CircularProgress size={20} /> : <VisibilityIcon />}
                          </IconButton>
                        </Box>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )
            }
          </Box>
          <Dialog open={fileViewer.open} onClose={handleCloseFileViewer} maxWidth="md" fullWidth scroll="paper">
            <DialogTitle>Viewing: {fileViewer.filename}</DialogTitle>
            <DialogContent dividers>
              <Paper elevation={0} sx={{ p: 2, maxHeight: '70vh', overflow: 'auto', backgroundColor: '#f5f5f5' }}>
                <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: '0.875rem' }}>
                  {fileViewer.content}
                </pre>
              </Paper>
            </DialogContent>
            <DialogActions>
              <Button onClick={handleCloseFileViewer}>Close</Button>
            </DialogActions>
          </Dialog>
        </Paper>
      )}
      {/* Disable update and post-checks if AVANT critical error */}
      {avantCriticalError && (
        <Button variant="contained" color="primary" size="large" disabled sx={{ display: 'block', mx: 'auto', mb: 3, py: 1.5, px: 4, fontSize: '1.1rem', boxShadow: 3 }}>
          Perform Software Update
        </Button>
      )}
      {/* --- APRES Section --- */}
      {sessionData.avantCompleted && !apresCriticalError && (
        <Paper elevation={2} sx={{ p: {xs:2, md:3}, mb: 3, backgroundColor: '#e3f2fd' }}>
          <Box sx={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb:2, flexWrap: 'wrap', gap:1}}>
            <Typography variant="h5">Post-Update Informations</Typography>
            <Button 
              variant="outlined" 
              color="secondary" 
              onClick={handleReloadApres} 
              disabled={!sessionData.apresCompleted || showApresRunner} 
              sx={{ml:2, alignSelf: 'flex-end'}}
            >
              {showApresRunner ? <CircularProgress size={20} sx={{mr:1}} /> : null} Reload
            </Button>
          </Box>
          {!sessionData.apresCompleted && !showApresRunner && (
            <Button variant="contained" color="primary" onClick={handleTriggerApres}
              disabled={isActionLoading} sx={{mb:2}}
            > Run Post-Checks </Button>
          )}
          {showApresRunner && (
            <ApresRunner onApresProcessFinished={handleApresProcessFinished} />
          )}
          {showApresResultsDisplay && (
            <>
              <StructuredDataDisplay data={sessionData.apresData} titlePrefix="APRES" />
            </>
          )}
          {/* Compare button moved below content */}
          {sessionData.apresCompleted && sessionData.comparisonResults && Object.keys(sessionData.comparisonResults).length > 0 && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
              <Button variant="outlined" onClick={() => setShowComparisonDetailModal(true)}>
                Compare With Pre-Checks
              </Button>
            </Box>
          )}
        </Paper>
      )}
      {apresCriticalError && (
        <Box sx={{ width: '100%' }}>
          <Paper elevation={2} sx={{ p: 3, mb: 3, backgroundColor: '#fff3e0', textAlign: 'center' }}>
            <Alert severity="error" sx={{ mb: 2 }}>{apresCriticalError}</Alert>
            <Button variant="contained" color="primary" onClick={handleReloadApres}>Reload Post-Checks</Button>
          </Paper>
          <Button variant="outlined" color="primary" disabled sx={{ mt: 2 }}>
            Compare With Pre-Checks
          </Button>
        </Box>
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
        title="Pre-Checks Execution Logs"
      />      <ConfirmationModal
        open={showApresConfirmModal}
        onClose={handleCancelApres}
        title="Run APRES Without Update?"
        message="Would you like to run the APRES post-update checks without performing a software update? This will compare the current router state with the initial pre-checks."
        confirmText="Run Post-Checks"
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