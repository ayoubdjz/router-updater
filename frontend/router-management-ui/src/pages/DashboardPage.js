import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { toast } from 'react-toastify';
import IconButton from '@mui/material/IconButton';
import VisibilityIcon from '@mui/icons-material/Visibility';
// import DeleteIcon from '@mui/icons-material/Delete'; // Not used in the provided snippet, but kept if relevant elsewhere
import ApresRunner from '../components/Apres/ApresRunner';
import ConfirmationModal from '../components/Common/ConfirmationModal';
import StructuredDataDisplay from '../components/Common/StructuredDataDisplay';
import LogDisplay from '../components/Common/LogDisplay';
import ComparisonModal from '../components/Common/ComparisonModal';
import { useAuth } from '../contexts/AuthContext';
import { runAvantChecks, /* runUpdateProcedure, */ unlockRouter, listGeneratedFiles, getFileContent, deleteGeneratedFile } from '../api/routerApi'; // runUpdateProcedure removed
import LogModal from '../components/Common/LogModal';
// import UpdateModal from '../components/Update/UpdateModal'; // Removed
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';

const DashboardPage = () => {
  // --- Hooks ---
  const { sessionData, updateSession, resetWorkflow, credentials, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // --- State ---
  const [isAvantLoading, setIsAvantLoading] = useState(false);
  const [avantError, setAvantError] = useState('');
  const [avantLogs, setAvantLogs] = useState([]);
  const [avantCriticalError, setAvantCriticalError] = useState(null);

  const [isActionLoading, setIsActionLoading] = useState(false); // General purpose loading for dashboard actions like unlock
  const [actionError, setActionError] = useState(''); // General purpose error for dashboard actions
  const [dashboardActionLogs, setDashboardActionLogs] = useState([]);

  const [showApresConfirmModal, setShowApresConfirmModal] = useState(false);
  const [showComparisonDetailModal, setShowComparisonDetailModal] = useState(false);
  const [showAvantLogsModal, setShowAvantLogsModal] = useState(false);
  // const [showUpdateModal, setShowUpdateModal] = useState(false); // Removed

  const [avantFileAction, setAvantFileAction] = useState({ loading: false, type: null });

  const [generatedFiles, setGeneratedFiles] = useState([]);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [fileAction, setFileAction] = useState({ type: null, filename: null });
  const [fileViewer, setFileViewer] = useState({ open: false, content: '', filename: '' });

  // const [isUpdateLoading, setIsUpdateLoading] = useState(false); // Removed
  // const [updateLogs, setUpdateLogs] = useState([]); // Removed

  const [lastFailedAction, setLastFailedAction] = useState(null);
  const [apresCriticalError, setApresCriticalError] = useState(null);

  // --- Refs ---
  const initialAvantFetchInProgressRef = useRef(false);

  // --- Handler Functions (Defined BEFORE useEffect and conditional rendering logic) ---

  const handleReloadAvant = useCallback(async () => {
    setAvantCriticalError(null);
    setAvantError('');
    setAvantLogs([]);
    setIsAvantLoading(false); // Ensure this is reset so useEffect logic can proceed
    initialAvantFetchInProgressRef.current = false; // Reset ref

    updateSession({
      ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
      avantCompleted: false, avantData: null,
      // Removed updateAttempted: false, updateCompleted: false,
      apresCompleted: false, apresData: null, comparisonResults: null,
      viewState: 'initial'
    });
    // The main useEffect for AVANT will now re-evaluate and re-trigger if conditions are met.
  }, [updateSession]);

  const handleReloadApres = useCallback(() => {
    setApresCriticalError(null); // Clear APRES critical error
    updateSession({
      viewState: 'apres_running', // This should re-trigger the ApresRunner
      apresCompleted: false,
      apresData: null,
      comparisonResults: null
    });
  }, [updateSession]);

  // Removed handleTriggerUpdate and handleConfirmUpdate

  const handleTriggerApres = useCallback(() => {
    setShowApresConfirmModal(true);
  }, []);

  const handleConfirmApres = useCallback(() => {
    setShowApresConfirmModal(false);
    setApresCriticalError(null); // Clear previous APRES error before running
    updateSession({ viewState: 'apres_running' });
  }, [updateSession]);

  const handleCancelApres = useCallback(() => {
    setShowApresConfirmModal(false);
  }, []);

  const handleApresProcessFinished = useCallback((apresSuccess, apresData, comparisonResults, criticalErrorMsg) => {
    if (criticalErrorMsg) {
        setApresCriticalError(criticalErrorMsg);
        updateSession({
            apresCompleted: false,
            apresData: null, // Clear data on critical error
            comparisonResults: null,
            viewState: 'apres_error' // A new state to signify APRES critical failure
        });
        toast.error(`Post-checks failed critically: ${criticalErrorMsg}`);
    } else {
        setApresCriticalError(null); // Clear any previous critical error on success/non-critical issue
        updateSession({
            apresCompleted: true, // Even if not 100% "success", it "completed"
            apresData: apresData,
            comparisonResults: comparisonResults,
            viewState: apresSuccess ? 'workflow_complete' : 'apres_completed_with_issues',
            // If APRES was successful, assume lock is released as per API design.
            ...(apresSuccess ? { lock_file_path: null } : {})
        });
        if (apresSuccess) {
            toast.success("Post-checks completed successfully.");
        } else {
            toast.warn("Post-checks completed with issues. Please review the details.");
        }
    }
  }, [updateSession]);

  const handleForceUnlockAndFullReset = useCallback(async () => {
    if (!sessionData.lock_file_path) {
      const msg = "No lock file path known to attempt unlock.";
      toast.warn(msg); setActionError(msg); return;
    }
    setIsActionLoading(true); setActionError(''); setDashboardActionLogs([`Attempting force unlock for: ${sessionData.lock_file_path}`]);
    try {
      const unlockResponse = await unlockRouter(sessionData.lock_file_path);
      const unlockMsg = `Force Unlock: ${unlockResponse.data.message || 'Unlock attempted.'}`;
      setDashboardActionLogs(prev => [...prev, unlockMsg, ...(unlockResponse.data.logs || [])]);
      toast.info(unlockMsg);
      resetWorkflow(); // Resets session, should trigger full re-evaluation including AVANT
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'Failed to force unlock router.';
      setActionError(errorMsg); toast.error(errorMsg);
      setDashboardActionLogs(prevLogs => [...prevLogs, `Error during force unlock: ${errorMsg}`]);
    } finally {
      setIsActionLoading(false);
    }
  }, [sessionData.lock_file_path, resetWorkflow]);

  const fetchGeneratedFiles = useCallback(async () => {
    if (!sessionData.avantCompleted || avantCriticalError) return; // Don't fetch if AVANT isn't successfully done
    setIsLoadingFiles(true);
    try {
      const res = await listGeneratedFiles();
      setGeneratedFiles(res.data.files || []);
    } catch (err) {
      toast.error('Failed to fetch generated files list.');
      setGeneratedFiles([]);
    } finally {
      setIsLoadingFiles(false);
    }
  }, [sessionData.avantCompleted, avantCriticalError]);

  const handleViewFile = useCallback(async (filename) => {
    setFileAction({ type: 'view', filename });
    try {
      const res = await getFileContent(filename);
      setFileViewer({ open: true, content: res.data, filename });
    } catch (err) {
      toast.error(`Failed to fetch content for ${filename}: ${err.response?.data?.message || err.message}`);
    } finally {
      setFileAction({ type: null, filename: null });
    }
  }, []);

  const handleDeleteFile = useCallback(async (filename) => {
    if (!window.confirm(`Are you sure you want to delete the file: ${filename}? This action cannot be undone.`)) return;
    setFileAction({ type: 'delete', filename });
    try {
      const res = await deleteGeneratedFile(filename);
      toast.success(res.data.message || `File ${filename} deleted.`);
      setGeneratedFiles((prev) => prev.filter((f) => f !== filename));
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
  }, [sessionData.avant_file_path, sessionData.config_file_path, sessionData.lock_file_path, updateSession]);

  const handleCloseFileViewer = useCallback(() => {
    setFileViewer({ open: false, content: '', filename: '' });
  }, []);

  const handleViewAvantFile = useCallback(() => {
    if (!sessionData.avant_file_path) return;
    setAvantFileAction({ loading: true, type: 'view' });
    const fileName = sessionData.avant_file_path.split(/[/\\]/).pop();
    window.open(`/api/files/${encodeURIComponent(fileName)}`, '_blank');
    setTimeout(() => setAvantFileAction({ loading: false, type: null }), 500);
  }, [sessionData.avant_file_path]);

  const handleRetry = useCallback(async () => {
    if (!lastFailedAction) return;
    const { type /*, params */ } = lastFailedAction; // params might not be needed if update is removed
    setLastFailedAction(null); // Clear before retrying

    if (type === 'avant') {
      await handleReloadAvant();
    } else if (type === 'apres') {
      handleReloadApres();
    }
  }, [lastFailedAction, handleReloadAvant, handleReloadApres]); // Removed handleConfirmUpdate

  // --- Effects ---
  useEffect(() => {
    // Initial AVANT checks
    if (avantCriticalError || sessionData.avantCompleted || !credentials || isAvantLoading || initialAvantFetchInProgressRef.current) {
        if(avantCriticalError || sessionData.avantCompleted) initialAvantFetchInProgressRef.current = false;
        return;
    }

    const performInitialAvantChecks = async () => {
      initialAvantFetchInProgressRef.current = true;
      setIsAvantLoading(true);
      setAvantError(''); setAvantLogs([]);
      updateSession({
        ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
        avantCompleted: false, avantData: null, // Removed updateAttempted, updateCompleted
        apresCompleted: false, apresData: null, comparisonResults: null, viewState: 'avant_loading'
      });

      try {
        const response = await runAvantChecks(credentials);
        setAvantLogs(response.data.logs || []);
        if (response.data.status === 'success') {
          updateSession({
            ident_data: response.data.ident_data,
            lock_file_path: response.data.ident_data?.lock_file_path,
            avant_file_path: response.data.avant_file_path,
            config_file_path: response.data.config_file_path,
            avantCompleted: true, avantData: response.data.structured_data, viewState: 'avant_success'
          });
          setAvantError(''); toast.success("Pre-checks completed successfully!");
        } else {
          const errMsg = `AVANT checks failed: ${response.data.message || 'Unknown AVANT error'}`;
          setAvantError(errMsg); setAvantCriticalError(errMsg);
          toast.error('An error occurred during pre-checks. Please retry.');
          updateSession({ avantCompleted: false, viewState: 'avant_error' });
        }
      } catch (err) {
        const errorMsg = err.response?.data?.message || err.message || 'Network/Request Error during AVANT checks.';
        setAvantError(errorMsg); setAvantCriticalError(errorMsg);
        const errLogs = err.response?.data?.logs || [];
        setAvantLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
        toast.error(errorMsg);
        updateSession({ avantCompleted: false, viewState: 'avant_error' });
        if (err.response?.status === 401 || err.response?.status === 403) {
          logout();
          navigate('/login', { replace: true, state: { error: "Session issue during AVANT. Please login again." } });
        }
      } finally {
        setIsAvantLoading(false);
        initialAvantFetchInProgressRef.current = false;
      }
    };
    if (credentials && !sessionData.avantCompleted && !avantCriticalError && !isAvantLoading && !initialAvantFetchInProgressRef.current) {
        performInitialAvantChecks();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credentials, sessionData.avantCompleted, avantCriticalError, isAvantLoading, updateSession, logout, navigate]);


  useEffect(() => {
    if (sessionData.avantCompleted && !avantCriticalError) {
      fetchGeneratedFiles();
    }
  }, [sessionData.avantCompleted, avantCriticalError, fetchGeneratedFiles]);


  // --- Conditional Rendering Logic / View States ---
  const showInitialAvantLoadingState = isAvantLoading && !avantCriticalError && !sessionData.avantCompleted;
  const showAvantCriticalErrorState = avantCriticalError && !sessionData.avantCompleted;
  const showAvantNotRunMessage = !credentials || (!sessionData.avantCompleted && !isAvantLoading && !avantCriticalError && !showInitialAvantLoadingState);
  const showAvantResultsSection = sessionData.avantCompleted && !avantCriticalError;
  const showApresRunner = showAvantResultsSection && sessionData.viewState === 'apres_running' && !sessionData.apresCompleted && !apresCriticalError;
  const showApresResultsDisplay = sessionData.apresCompleted && sessionData.apresData && !apresCriticalError;

  // --- Early Returns (Order Matters) ---
  if (showInitialAvantLoadingState) {
    return (
      <Paper elevation={3} sx={{ p: 3, textAlign: 'center', mt: 4 }}>
        <CircularProgress size={60} /> <Typography variant="h6" sx={{ mt: 2 }}>Running Pre-Checks</Typography>
        <Box sx={{ width: '80%', margin: '20px auto' }}><LogDisplay logs={avantLogs} title="Initial AVANT Logs" /></Box>
      </Paper>
    );
  }

  if (showAvantCriticalErrorState) {
    return (
      <Paper elevation={3} sx={{ p: 3, mt: 4, textAlign: 'center' }}>
        <Alert severity="error" sx={{ mb: 2 }}>AVANT Pre-Checks Failed Critically: {avantCriticalError}</Alert>
        <Box sx={{mt: 2, display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
            <Button onClick={handleReloadAvant} variant="contained">Retry Pre-Checks</Button>
            <Button onClick={() => { logout(); navigate('/login', { replace: true }); }} variant="outlined">Logout</Button>
            {sessionData.lock_file_path && (
                <Button onClick={handleForceUnlockAndFullReset} variant="text" color="error" size="small">Force Unlock & Reset Workflow</Button>
            )}
        </Box>
      </Paper>
    );
  }

  if (showAvantNotRunMessage) {
    return (
      <Paper elevation={3} sx={{ p: 3, textAlign: 'center', mt: 4 }}>
        <Typography>Please wait for Pre-Checks to initialize or complete login...</Typography>
        <CircularProgress sx={{ mt: 2 }} />
      </Paper>
    );
  }

  // --- Main Component JSX ---
  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="h4" gutterBottom sx={{ textAlign: 'center', mb: 1 }}>Router Operations</Typography>
      <Typography variant="subtitle1" sx={{ textAlign: 'center', mb: 3 }}>
        Device: {sessionData.ident_data?.ip || 'N/A'} (Hostname: {sessionData.ident_data?.router_hostname || 'N/A'})
      </Typography>

      {actionError && <Alert severity="error" sx={{ my: 2 }}>{actionError}</Alert>}
      {lastFailedAction && (
        <Alert severity="warning" sx={{ my: 2 }} action={
          <Button color="inherit" size="small" onClick={handleRetry}>RETRY ({lastFailedAction.type.toUpperCase()})</Button>
        }>
          Last action ({lastFailedAction.type}) failed. You can try again.
        </Alert>
      )}
      {dashboardActionLogs.length > 0 && <LogDisplay logs={dashboardActionLogs} title="Dashboard Action Logs" />}

      {/* AVANT Results Section */}
      {showAvantResultsSection && (
        <Paper elevation={2} sx={{ p: { xs: 2, md: 3 }, mb: 3, backgroundColor: 'hsl(207, 73%, 94%)' /* light blue */ }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
            <Typography variant="h5">Pre-Check Information</Typography>
            <Button variant="outlined" color="secondary" onClick={handleReloadAvant} disabled={isAvantLoading}>
              {isAvantLoading ? <CircularProgress size={20} sx={{ mr: 1 }} /> : null} Reload Pre-Checks
            </Button>
          </Box>
          <StructuredDataDisplay data={sessionData.avantData} titlePrefix="AVANT" />
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <Button variant="outlined" onClick={() => setShowAvantLogsModal(true)}>Show Pre-Checks Logs</Button>
          </Box>
          <Divider sx={{ my: 3 }}><Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#1976d2' }}>Generated Files</Typography></Divider>
          {isLoadingFiles ? <CircularProgress sx={{ display: 'block', margin: 'auto', my: 2 }} /> :
            generatedFiles.length === 0 ? (
              <Typography sx={{ fontStyle: 'italic', textAlign: 'center' }}>No additional files found.</Typography>
            ) : (
              <Grid container spacing={1.5}>
                {generatedFiles.map((file) => (
                  <Grid item xs={12} sm={6} md={4} key={file}>
                    <Paper elevation={1} sx={{ p: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Typography variant="body2" sx={{ wordBreak: 'break-all', mr:1, flexGrow: 1 }}>{file}</Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexShrink: 0 }}>
                        <IconButton size="small" title={`View ${file}`} onClick={() => handleViewFile(file)} disabled={fileAction.type === 'view' && fileAction.filename === file}>
                          {(fileAction.type === 'view' && fileAction.filename === file) ? <CircularProgress size={16} /> : <VisibilityIcon fontSize="small" />}
                        </IconButton>
                      </Box>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            )}
        </Paper>
      )}

      {/* --- Separator between Pre-Check and Post-Checks Sections --- */}
      {showAvantResultsSection && (
        <Divider sx={{ my: 4 }}>
          <Typography variant="h6" sx={{ color: '#1976d2', fontWeight: 700, letterSpacing: 1 }}>
            Post-Checks Section
          </Typography>
        </Divider>
      )}

      {/* APRES Section */}
      {showAvantResultsSection && (
        <>
          {apresCriticalError && (
            <Paper elevation={2} sx={{ p: 3, mb: 3, backgroundColor: 'hsl(0, 70%, 94%)' /* light red */, textAlign: 'center' }}>
              <Alert severity="error" sx={{ mb: 2 }}>Post-Checks Failed Critically: {apresCriticalError}</Alert>
              <Button variant="contained" color="primary" onClick={handleReloadApres}>Retry Post-Checks</Button>
            </Paper>
          )}

          {!apresCriticalError && (
            <Paper elevation={2} sx={{ p: { xs: 2, md: 3 }, mb: 3, backgroundColor: 'hsl(207, 73%, 94%)' /* light purple in intent, actual color might differ */ }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
                <Typography variant="h5">Post-Checks Information</Typography>
                {(!showApresRunner && !sessionData.apresCompleted) && (
                  <Button variant="contained" color="secondary" onClick={handleTriggerApres} disabled={isActionLoading}>Run Post-Checks</Button>
                )}
                {sessionData.apresCompleted && (
                   <Button variant="outlined" color="secondary" onClick={handleReloadApres} disabled={showApresRunner}>
                    {showApresRunner ? <CircularProgress size={20} sx={{mr:1}}/> : null} Reload Post-Checks</Button>
                )}
              </Box>

              {showApresRunner && ( <ApresRunner onApresProcessFinished={handleApresProcessFinished} /> )}
              {/* For debugging APRES data: console.log('sessionData.apresData for display:', sessionData.apresData) */}
              {showApresResultsDisplay && (
                <>
                  <StructuredDataDisplay data={sessionData.apresData} titlePrefix="APRES" />
                  {sessionData.comparisonResults && Object.keys(sessionData.comparisonResults).length > 0 && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                      <Button variant="outlined" onClick={() => setShowComparisonDetailModal(true)}>Compare Pre/Post Checks</Button>
                    </Box>
                  )}
                </>
              )}
               {sessionData.viewState === 'apres_completed_with_issues' && !apresCriticalError && (
                <Alert severity="warning" sx={{mt:2}}>Post-checks completed with some discrepancies. Review logs and comparison.</Alert>
              )}
            </Paper>
          )}
        </>
      )}

      {/* Modals */}
      <ComparisonModal open={showComparisonDetailModal} onClose={() => setShowComparisonDetailModal(false)} comparisonResults={sessionData.comparisonResults}/>
      <LogModal open={showAvantLogsModal} onClose={() => setShowAvantLogsModal(false)} logs={avantLogs} title="Pre-Checks Execution Logs"/>
      <ConfirmationModal open={showApresConfirmModal} onClose={handleCancelApres} title="Run Post-Checks"
        message="Are you ready to run the post-checks? This will compare the current state against the initial pre-checks."
        confirmText="Run Post-Checks" cancelText="Cancel" onConfirm={handleConfirmApres}
      />
      {/* <UpdateModal open={showUpdateModal} onClose={() => setShowUpdateModal(false)} onConfirm={handleConfirmUpdate} isLoading={isUpdateLoading} logs={updateLogs}/> // Removed */}
      <Dialog open={fileViewer.open} onClose={handleCloseFileViewer} maxWidth="lg" fullWidth scroll="paper">
        <DialogTitle>Viewing: {fileViewer.filename}</DialogTitle>
        <DialogContent dividers>
          <Paper elevation={0} sx={{ p: 2, maxHeight: '75vh', overflow: 'auto', backgroundColor: '#f5f5f5' }}>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: '0.875rem' }}>
              {fileViewer.content || "No content or file is empty."}
            </pre>
          </Paper>
        </DialogContent>
        <DialogActions><Button onClick={handleCloseFileViewer}>Close</Button></DialogActions>
      </Dialog>
    </Box>
  );
};

export default DashboardPage;
