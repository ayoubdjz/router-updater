import { useState, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { toast } from 'react-toastify';

export const useApresChecks = (setLastFailedAction) => {
  const { updateSession } = useAuth();
  const [showApresConfirmModal, setShowApresConfirmModal] = useState(false);
  const [apresCriticalError, setApresCriticalError] = useState(null); // Local state for critical error message

  const handleTriggerApres = useCallback(() => {
    setShowApresConfirmModal(true);
  }, []);

  const handleConfirmApres = useCallback(() => {
    setShowApresConfirmModal(false);
    setApresCriticalError(null);
    setLastFailedAction(null);
    updateSession({ viewState: 'apres_running', apresCompleted: false, apresData: null, comparisonResults: null });
  }, [updateSession, setLastFailedAction]);

  const handleCancelApres = useCallback(() => {
    setShowApresConfirmModal(false);
  }, []);

  const handleApresProcessFinished = useCallback((apresSuccess, apresData, comparisonResults, criticalErrorMsg, apresLogs) => {
    if (criticalErrorMsg) {
      setApresCriticalError(criticalErrorMsg);
      updateSession({
        apresCompleted: false,
        apresData: null,
        comparisonResults: null,
        apresLogs: apresLogs || [],
        viewState: 'apres_error'
      });
      setLastFailedAction({ type: 'apres', message: criticalErrorMsg });
      toast.error(`Post-checks failed critically: ${criticalErrorMsg}`);
    } else {
      setApresCriticalError(null);
      updateSession({
        apresCompleted: true,
        apresData: apresData,
        comparisonResults: comparisonResults, // This is the string from ApresRunner
        apresLogs: apresLogs || [],
        viewState: apresSuccess ? 'workflow_complete' : 'apres_completed_with_issues',
        ...(apresSuccess ? { lock_file_path: null } : {}) // Clear lock file on full success
      });
      if (apresSuccess) {
        toast.success("Post-checks completed successfully.");
      } else {
        toast.warn("Post-checks completed with issues. Please review the details.");
      }
    }
  }, [updateSession, setLastFailedAction]);

  const handleReloadApres = useCallback(() => {
    setApresCriticalError(null);
    updateSession({
      viewState: 'apres_running', // This will re-trigger the ApresRunner if visible
      apresCompleted: false,
      apresData: null,
      comparisonResults: null
    });
  }, [updateSession]);


  return {
    showApresConfirmModal,
    apresCriticalError, // The message itself
    handleTriggerApres,
    handleConfirmApres,
    handleCancelApres,
    handleApresProcessFinished,
    handleReloadApres, // This can be used as retryApres
  };
};