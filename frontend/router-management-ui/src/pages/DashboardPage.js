import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } // useLocation not directly used now
from 'react-router-dom';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import Divider from '@mui/material/Divider';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
// import { toast } from 'react-toastify'; // Toasts are now handled within hooks

import { useAuth } from '../contexts/AuthContext';
import LogDisplay from '../components/Common/LogDisplay';

// Hooks
import { useAvantChecks } from '../hooks/useAvantChecks';
import { useSoftwareUpdate } from '../hooks/useSoftwareUpdate';
import { useApresChecks } from '../hooks/useApresChecks';
import { useGeneratedFiles } from '../hooks/useGeneratedFiles';
import { useDashboardGeneral } from '../hooks/useDashboardGeneral';

// Sections
import AvantSection from '../components/Dashboard/AvantSection';
import UpdateSection from '../components/Dashboard/UpdateSection';
import ApresSection from '../components/Dashboard/ApresSection';

// Modals Container
import DashboardModals from '../components/Dashboard/DashboardModals';

const DashboardPage = () => {
  const { sessionData, logout } = useAuth();
  const navigate = useNavigate();

  // General Dashboard State Hook
  const {
    isActionLoading, // For general buttons like Force Unlock
    actionError,
    // setActionError,
    dashboardActionLogs,
    // setDashboardActionLogs,
    lastFailedAction,
    setLastFailedAction,
    handleForceUnlockAndFullReset,
  } = useDashboardGeneral();

  // AVANT Checks Hook
  const {
    isAvantLoading,
    avantLogs,
    avantCriticalError,
    handleReloadAvant,
    initialAvantFetchInProgressRef,
  } = useAvantChecks(setLastFailedAction);

  // Software Update Hook
  const {
    isUpdateModalOpen,
    // updateImageFilename, // Managed internally by hook, exposed for retry if needed
    isStreamingLogModalOpen,
    streamingUpdateLogs,
    isUpdateInProgress: isUpdateInProgressHook, // Renamed to avoid conflict with sessionData.updateInProgress
    updateOperationResult,
    handleOpenUpdateModal,
    handleCloseUpdateModal,
    handleStartUpdateProcedure,
    handleCloseStreamingLogModal,
    retryUpdate,
    setUpdateImageFilename, // For UpdateModal to set it
  } = useSoftwareUpdate(setLastFailedAction);

  // APRES Checks Hook
  const {
    showApresConfirmModal,
    apresCriticalError: apresHookCriticalError, // Renamed to avoid conflict
    handleTriggerApres,
    handleConfirmApres,
    handleCancelApres,
    handleApresProcessFinished,
    handleReloadApres, // Also used as retryApres
  } = useApresChecks(setLastFailedAction);

  // Generated Files Hook
  const generatedFilesHook = useGeneratedFiles(sessionData.avantCompleted, avantCriticalError);
  const {
    fileViewer,
    handleViewFile,
    handleCloseFileViewer,
    // ...other props
    ...restGeneratedFilesProps
  } = generatedFilesHook;
  const generatedFilesProps = { handleViewFile, ...restGeneratedFilesProps };

  // Modal States (some are local to DashboardPage for controlling modal visibility)
  const [showAvantLogsModal, setShowAvantLogsModal] = useState(false);
  const [showComparisonDetailModal, setShowComparisonDetailModal] = useState(false);
  const [showApresLogsModal, setShowApresLogsModal] = useState(false);


  // Centralized Retry Handler
  const handleRetry = useCallback(async () => {
    if (!lastFailedAction) return;
    const { type } = lastFailedAction;
    setLastFailedAction(null); // Clear after attempting retry

    if (type === 'avant') {
      // handleReloadAvant already resets and triggers performAvantChecks via useEffect in useAvantChecks
      // Or, if more direct control is needed:
      // setAvantCriticalError(null); // Assuming setAvantCriticalError is exposed by useAvantChecks
      // performAvantChecks(); 
      handleReloadAvant();
    } else if (type === 'apres') {
      handleReloadApres(); // This re-triggers the ApresRunner or relevant state
    } else if (type === 'update') {
      retryUpdate(); // Call the retry function from useSoftwareUpdate
    }
  }, [lastFailedAction, setLastFailedAction, handleReloadAvant, handleReloadApres, retryUpdate /*, performAvantChecks (if used directly) */]);


  // --- Conditional Rendering Logic / View States ---
  // Use initialAvantFetchInProgressRef for the very first loading screen
  const showInitialAvantLoadingState = initialAvantFetchInProgressRef.current && isAvantLoading && !avantCriticalError && !sessionData.avantCompleted;
  const showAvantCriticalErrorState = avantCriticalError && !sessionData.avantCompleted;
  const showAvantNotRunMessage = !sessionData.credentials && !sessionData.avantCompleted && !isAvantLoading && !avantCriticalError && !showInitialAvantLoadingState;


  // --- Early Returns (Order Matters) ---
  if (showInitialAvantLoadingState) {
    return (
      <Paper elevation={3} sx={{ p: 3, textAlign: 'center', my: 2 }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 2 }}>Running AVANT Pre-Checks...</Typography>
        <Typography variant="body2">Please wait, this may take a few moments.</Typography>
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
            {sessionData.lock_file_path && ( // sessionData still holds lock_file_path
                <Button onClick={handleForceUnlockAndFullReset} variant="text" color="error" size="small" disabled={isActionLoading}>
                    {isActionLoading && <CircularProgress size={16} sx={{mr:1}} />}
                    Force Unlock & Reset Workflow
                </Button>
            )}
        </Box>
        <Button variant="outlined" sx={{ mt: 3 }} onClick={() => setShowAvantLogsModal(true)}>
          Voir les logs AVANT
        </Button>
      </Paper>
    );
  }
  
  // This condition might need adjustment based on how credentials flow and initial auth state
  if (showAvantNotRunMessage) {
    return (
      <Paper elevation={3} sx={{ p: 3, textAlign: 'center', mt: 4 }}>
        <Typography>Please login or wait for Pre-Checks to initialize...</Typography>
        <CircularProgress sx={{ mt: 2 }} />
      </Paper>
    );
  }

  const showAvantResultsSection = sessionData.avantCompleted && !avantCriticalError;
  const showApresSection = showAvantResultsSection;


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
          Last action ({lastFailedAction.type}) failed: {lastFailedAction.message}. You can try again.
        </Alert>
      )}
      {dashboardActionLogs.length > 0 && <LogDisplay logs={dashboardActionLogs} title="Dashboard Action Logs" />}

      {/* Update Section always available if AVANT is complete */}
      {showAvantResultsSection && (
        <UpdateSection
          handleOpenUpdateModal={handleOpenUpdateModal}
          isUpdateInProgressHook={isUpdateInProgressHook}
          updateOperationResult={updateOperationResult}
          retryUpdate={retryUpdate}
        />
      )}
      
      {/* AVANT Results Section (includes Generated Files) */}
      {showAvantResultsSection && (
        <AvantSection
          isAvantLoading={isAvantLoading}
          handleReloadAvant={handleReloadAvant}
          setShowAvantLogsModal={() => setShowAvantLogsModal(true)}
          generatedFilesProps={generatedFilesProps}
        />
      )}

      {/* Separator and APRES Section */}
      {showApresSection && (
        <>
          <Divider sx={{ my: 4 }}>
            <Typography variant="h6" sx={{ color: '#1976d2', fontWeight: 700, letterSpacing: 1 }}>
              Post-Checks Section
            </Typography>
          </Divider>
          <ApresSection
            apresCriticalError={apresHookCriticalError}
            handleTriggerApres={handleTriggerApres}
            handleReloadApres={handleReloadApres}
            handleApresProcessFinished={handleApresProcessFinished}
            setShowComparisonDetailModal={() => setShowComparisonDetailModal(true)}
            setShowApresLogsModal={() => setShowApresLogsModal(true)}
            // isActionLoading={isActionLoading} // Pass if Apres buttons depend on general loading
          />
        </>
      )}
      
      <DashboardModals
        showComparisonDetailModal={showComparisonDetailModal}
        closeComparisonDetailModal={() => setShowComparisonDetailModal(false)}
        comparisonResults={sessionData.comparisonResults}
        
        showAvantLogsModal={showAvantLogsModal}
        closeAvantLogsModal={() => setShowAvantLogsModal(false)}
        avantLogs={avantLogs}

        
        showApresConfirmModal={showApresConfirmModal}
        closeApresConfirmModal={handleCancelApres}
        confirmApres={handleConfirmApres}
        
        isUpdateModalOpen={isUpdateModalOpen}
        closeUpdateModal={handleCloseUpdateModal}
        startUpdateProcedure={(filename) => {
            setUpdateImageFilename(filename); // Ensure filename is set in hook for retries
            handleStartUpdateProcedure(filename);
        }}
        
        isStreamingLogModalOpen={isStreamingLogModalOpen}
        closeStreamingLogModal={handleCloseStreamingLogModal}
        streamingUpdateLogs={streamingUpdateLogs}
        isUpdateInProgress={isUpdateInProgressHook} // Pass hook's state
        updateOperationResult={updateOperationResult}
        
        fileViewerOpen={fileViewer.open}
        closeFileViewerModal={handleCloseFileViewer}
        fileViewerContent={fileViewer.content}
        fileViewerFilename={fileViewer.filename}

        showAprestLogsModal={showApresLogsModal}
        closeApresLogsModal={() => setShowApresLogsModal(false)}
        apresLogs={sessionData.apresLogs}
        
      />

    </Box>
  );
};

export default DashboardPage;