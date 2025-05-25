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
import { runAvantChecks, unlockRouter, listGeneratedFiles, getFileContent, deleteGeneratedFile, API_BASE_URL } from '../api/routerApi'; // runUpdateProcedure removed, API_BASE_URL added
import LogModal from '../components/Common/LogModal';
import UpdateModal from '../components/Update/UpdateModal'; // Re-added
import StreamingLogModal from '../components/Update/StreamingLogModal'; // New
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

  const [isActionLoading, setIsActionLoading] = useState(false); 
  const [actionError, setActionError] = useState(''); 
  const [dashboardActionLogs, setDashboardActionLogs] = useState([]);

  const [showApresConfirmModal, setShowApresConfirmModal] = useState(false);
  const [showComparisonDetailModal, setShowComparisonDetailModal] = useState(false);
  const [showAvantLogsModal, setShowAvantLogsModal] = useState(false);
  
  const [isUpdateModalOpen, setIsUpdateModalOpen] = useState(false); // For filename input
  const [updateImageFilename, setUpdateImageFilename] = useState(''); // To store the filename

  const [isStreamingLogModalOpen, setIsStreamingLogModalOpen] = useState(false); // For streaming logs
  const [streamingUpdateLogs, setStreamingUpdateLogs] = useState([]);
  const [isUpdateInProgress, setIsUpdateInProgress] = useState(false);
  const [updateOperationResult, setUpdateOperationResult] = useState(null); // {status, message, data}

  const [avantFileAction, setAvantFileAction] = useState({ loading: false, type: null });

  const [generatedFiles, setGeneratedFiles] = useState([]);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [fileAction, setFileAction] = useState({ type: null, filename: null });
  const [fileViewer, setFileViewer] = useState({ open: false, content: '', filename: '' });

  const [lastFailedAction, setLastFailedAction] = useState(null);
  const [apresCriticalError, setApresCriticalError] = useState(null);

  // --- Refs ---
  const initialAvantFetchInProgressRef = useRef(false);
  const abortControllerRef = useRef(null); // For aborting fetch stream

  // --- Handler Functions ---

  const handleReloadAvant = useCallback(async () => {
    setAvantCriticalError(null);
    setAvantError('');
    setAvantLogs([]);
    setIsAvantLoading(false); 
    initialAvantFetchInProgressRef.current = false; 

    updateSession({
      ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
      avantCompleted: false, avantData: null,
      updateAttempted: false, updateCompleted: false, updateInProgress: false, // Reset update states too
      apresCompleted: false, apresData: null, comparisonResults: null,
      viewState: 'initial'
    });
  }, [updateSession]);

  const handleReloadApres = useCallback(() => {
    setApresCriticalError(null); 
    updateSession({
      viewState: 'apres_running', 
      apresCompleted: false,
      apresData: null,
      comparisonResults: null
    });
  }, [updateSession]);

  // --- Update Procedure Handlers ---
  const handleOpenUpdateModal = () => {
    setIsUpdateModalOpen(true);
  };

  const handleCloseUpdateModal = () => {
    setIsUpdateModalOpen(false);
    setUpdateImageFilename(''); // Clear filename if modal is closed without starting
  };

  const handleStartUpdateProcedure = useCallback(async (imageFilenameFromModal) => {
    if (!credentials || !sessionData.ident_data) {
        toast.error("Cannot start update: Missing credentials or pre-check data.");
        return;
    }
    setUpdateImageFilename(imageFilenameFromModal);
    setIsUpdateModalOpen(false); // Close input modal
    setIsStreamingLogModalOpen(true); // Open streaming log modal
    setIsUpdateInProgress(true);
    setStreamingUpdateLogs([]);
    setUpdateOperationResult(null);
    updateSession({ updateAttempted: true, updateCompleted: false, updateInProgress: true });

    abortControllerRef.current = new AbortController();
    const { signal } = abortControllerRef.current;

    try {
        const response = await fetch(`${API_BASE_URL}/run_update`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ident_data: sessionData.ident_data,
                password: credentials.password,
                image_file: imageFilenameFromModal,
                // skip_re0_final_switchback: false, // Example: make this configurable if needed
            }),
            signal, // Pass the abort signal to fetch
        });

        if (!response.ok) {
            // Handle non-2xx HTTP responses that are not stream errors
            const errorData = await response.json().catch(() => ({ message: `HTTP error ${response.status}` }));
            throw new Error(errorData.message || `Server responded with ${response.status}`);
        }
        
        if (!response.body) {
            throw new Error("Response body is null, cannot stream.");
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        // eslint-disable-next-line no-constant-condition
        while (true) {
            const { done, value } = await reader.read();
            if (done) {
                if (!updateOperationResult) { // If stream ended without a complete/error event
                    setUpdateOperationResult({ status: 'warning', message: 'Update stream ended unexpectedly. Check server logs.' });
                }
                break;
            }

            buffer += decoder.decode(value, { stream: true });
            let boundary = buffer.indexOf('\n\n');

            while (boundary >= 0) {
                const message = buffer.substring(0, boundary);
                buffer = buffer.substring(boundary + 2);
                
                if (message.startsWith('data:')) {
                    try {
                        const jsonData = JSON.parse(message.substring(5)); // Skip 'data:'
                        if (jsonData.type === 'log') {
                            setStreamingUpdateLogs(prev => [...prev, jsonData.message]);
                        }
                    } catch (e) {
                        console.error("Failed to parse SSE log data:", e, "Raw data:", message);
                        setStreamingUpdateLogs(prev => [...prev, `[RAW/Parse Error]: ${message.substring(5)}`]);
                    }
                } else if (message.startsWith('event:')) {
                    const lines = message.split('\n');
                    const eventLine = lines.find(line => line.startsWith('event:'));
                    const dataLine = lines.find(line => line.startsWith('data:'));

                    if (eventLine && dataLine) {
                        const eventType = eventLine.substring(6).trim(); // Skip 'event:'
                        try {
                            const eventData = JSON.parse(dataLine.substring(5).trim()); // Skip 'data:'
                            if (eventType === 'update_complete') {
                                setUpdateOperationResult(eventData); // {status, message, updated_junos_info}
                                updateSession({ updateCompleted: true, updateInProgress: false });
                                if (eventData.status === 'success') toast.success(eventData.message || "Update completed successfully!");
                                else if (eventData.status === 'success_with_warning') toast.warn(eventData.message || "Update completed with warnings.");
                                else toast.error(eventData.message || "Update finished with errors.");
                                reader.cancel(); // Stop reading further if we got the final status
                                return; // Exit the loop and function
                            } else if (eventType === 'update_error') {
                                setUpdateOperationResult(eventData); // {status: 'error', message}
                                updateSession({ updateCompleted: false, updateInProgress: false });
                                toast.error(eventData.message || "A critical error occurred during the update stream.");
                                reader.cancel();
                                return;
                            }
                        } catch (e) {
                             console.error("Failed to parse SSE event data:", e, "Raw event:", message);
                             setStreamingUpdateLogs(prev => [...prev, `[RAW Event/Parse Error]: ${message}`]);
                        }
                    }
                }
                boundary = buffer.indexOf('\n\n');
            }
        }
    } catch (err) {
        if (err.name === 'AbortError') {
            setUpdateOperationResult({ status: 'info', message: 'Update operation aborted by user.' });
            toast.info('Update operation aborted.');
        } else {
            setUpdateOperationResult({ status: 'error', message: `Failed to run update: ${err.message}` });
            toast.error(`Update failed: ${err.message}`);
        }
        updateSession({ updateCompleted: false, updateInProgress: false });
    } finally {
        setIsUpdateInProgress(false);
        abortControllerRef.current = null; // Clear the abort controller
        // The modal (StreamingLogModal) remains open for the user to see the final status/logs
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credentials, sessionData.ident_data, updateSession]); // updateOperationResult is not a dependency here

  const handleCloseStreamingLogModal = () => {
    setIsStreamingLogModalOpen(false);
    // Optionally reset logs and status if modal is closed, or keep them for re-opening.
    // For now, we keep them until a new update starts.
    if (isUpdateInProgress && abortControllerRef.current) {
        abortControllerRef.current.abort(); // Abort fetch if modal is closed while in progress
    }
  };
  // --- End Update Procedure Handlers ---


  const handleTriggerApres = useCallback(() => {
    setShowApresConfirmModal(true);
  }, []);

  const handleConfirmApres = useCallback(() => {
    setShowApresConfirmModal(false);
    setApresCriticalError(null); 
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
            apresData: null, 
            comparisonResults: null,
            viewState: 'apres_error' 
        });
        toast.error(`Post-checks failed critically: ${criticalErrorMsg}`);
    } else {
        setApresCriticalError(null); 
        updateSession({
            apresCompleted: true, 
            apresData: apresData,
            comparisonResults: comparisonResults,
            viewState: apresSuccess ? 'workflow_complete' : 'apres_completed_with_issues',
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
      resetWorkflow(); 
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'Failed to force unlock router.';
      setActionError(errorMsg); toast.error(errorMsg);
      setDashboardActionLogs(prevLogs => [...prevLogs, `Error during force unlock: ${errorMsg}`]);
    } finally {
      setIsActionLoading(false);
    }
  }, [sessionData.lock_file_path, resetWorkflow]);

  const fetchGeneratedFiles = useCallback(async () => {
    if (!sessionData.avantCompleted || avantCriticalError) return; 
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
    const { type } = lastFailedAction; 
    setLastFailedAction(null); 

    if (type === 'avant') {
      await handleReloadAvant();
    } else if (type === 'apres') {
      handleReloadApres();
    } else if (type === 'update') {
        if (updateImageFilename) { // Ensure we have a filename to retry with
            handleStartUpdateProcedure(updateImageFilename);
        } else {
            toast.warn("Cannot retry update: Image filename not available. Please start the update process again.");
            setIsUpdateModalOpen(true); // Re-open input modal if no filename
        }
    }
  }, [lastFailedAction, handleReloadAvant, handleReloadApres, handleStartUpdateProcedure, updateImageFilename]); 

  // --- Effects ---
  useEffect(() => {
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
        avantCompleted: false, avantData: null, 
        updateAttempted: false, updateCompleted: false, updateInProgress: false,
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
          setLastFailedAction({ type: 'avant' });
        }
      } catch (err) {
        const errorMsg = err.response?.data?.message || err.message || 'Network/Request Error during AVANT checks.';
        setAvantError(errorMsg); setAvantCriticalError(errorMsg);
        const errLogs = err.response?.data?.logs || [];
        setAvantLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
        toast.error(errorMsg);
        updateSession({ avantCompleted: false, viewState: 'avant_error' });
        setLastFailedAction({ type: 'avant' });
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

  // Cleanup EventSource on component unmount or if update is re-initiated while one is active
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);


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

      {/* Software Update Button - Placed above Pre-Checks Section */}
      {showAvantResultsSection && !sessionData.updateInProgress && !sessionData.updateCompleted && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 2, py:1, borderBottom: '1px solid #e0e0e0', borderTop: '1px solid #e0e0e0' }}>
          <Button 
            variant="contained" 
            color="primary" 
            onClick={handleOpenUpdateModal}
            disabled={isUpdateInProgress}
          >
            {isUpdateInProgress ? <CircularProgress size={24} sx={{mr:1}} /> : null}
            Start Software Update
          </Button>
        </Box>
      )}
       {sessionData.updateInProgress && (
         <Alert severity="info" sx={{ my: 2 }}>Software update in progress...</Alert>
       )}
       {sessionData.updateCompleted && updateOperationResult && (
         <Alert severity={updateOperationResult.status === 'success' ? 'success' : updateOperationResult.status === 'success_with_warning' ? 'warning' : 'error'} sx={{ my: 2 }}>
           Update Finished: {updateOperationResult.message}
           {updateOperationResult.status !== 'success' &&
            <Button color="inherit" size="small" onClick={() => handleStartUpdateProcedure(updateImageFilename)} sx={{ml:2}}>RETRY UPDATE</Button>
           }
         </Alert>
       )}


      {/* AVANT Results Section */}
      {showAvantResultsSection && (
        <Paper elevation={2} sx={{ p: { xs: 2, md: 3 }, mb: 3, backgroundColor: 'hsl(207, 73%, 94%)' /* light blue */ }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
            <Typography variant="h5">Pre-Check Information</Typography>
            <Button variant="outlined" color="secondary" onClick={handleReloadAvant} disabled={isAvantLoading || isUpdateInProgress}>
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
      {showAvantResultsSection && (sessionData.updateCompleted || !sessionData.updateAttempted) && ( // Show only if update is done or not started
        <Divider sx={{ my: 4 }}>
          <Typography variant="h6" sx={{ color: '#1976d2', fontWeight: 700, letterSpacing: 1 }}>
            Post-Checks Section
          </Typography>
        </Divider>
      )}

      {/* APRES Section */}
      {showAvantResultsSection && (sessionData.updateCompleted || !sessionData.updateAttempted) && ( // Show only if update is done or not started
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
                  <Button variant="contained" color="secondary" onClick={handleTriggerApres} disabled={isActionLoading || isUpdateInProgress}>Run Post-Checks</Button>
                )}
                {sessionData.apresCompleted && (
                   <Button variant="outlined" color="secondary" onClick={handleReloadApres} disabled={showApresRunner || isUpdateInProgress}>
                    {showApresRunner ? <CircularProgress size={20} sx={{mr:1}}/> : null} Reload Post-Checks</Button>
                )}
              </Box>

              {showApresRunner && ( <ApresRunner onApresProcessFinished={handleApresProcessFinished} /> )}
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
      <UpdateModal 
        open={isUpdateModalOpen} 
        onClose={handleCloseUpdateModal} 
        onConfirm={handleStartUpdateProcedure} // This now directly triggers the stream
      />
      <StreamingLogModal
        open={isStreamingLogModalOpen}
        onClose={handleCloseStreamingLogModal}
        logs={streamingUpdateLogs}
        title="Software Update Progress"
        isLoading={isUpdateInProgress}
        finalStatus={updateOperationResult}
      />
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