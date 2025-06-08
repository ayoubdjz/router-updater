import { useState, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { toast } from 'react-toastify';
import { runApresChecks } from '../api/routerApi';

export const useApresChecks = (setLastFailedAction) => {
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [showApresConfirmModal, setShowApresConfirmModal] = useState(false);
  const [apresCriticalError, setApresCriticalError] = useState(null);
  const [apresCompleted, setApresCompleted] = useState(false);
  const [apresData, setApresData] = useState(null);
  const [comparisonResults, setComparisonResults] = useState(null);
  const [apresLogs, setApresLogs] = useState([]);
  const [apresLoading, setApresLoading] = useState(false);

  const handleTriggerApres = useCallback(() => {
    setShowApresConfirmModal(true);
  }, []);

  const handleConfirmApres = useCallback(() => {
    setShowApresConfirmModal(false);
    setApresCriticalError(null);
    setLastFailedAction(null);
    setApresCompleted(false);
    setApresData(null);
    setComparisonResults(null);
    setApresLogs([]);
    setApresLoading(true);
    // Start APRES fetch
    fetchApresChecks();
  }, [updateSession, setLastFailedAction]);

  const handleCancelApres = useCallback(() => {
    setShowApresConfirmModal(false);
  }, []);

  // Fetch logic for APRES
  const fetchApresChecks = useCallback(async () => {
    if (!credentials || !sessionData.ident_data) {
      const msg = "Authentication or AVANT session data missing for APRES.";
      setApresCriticalError(msg);
      setApresLoading(false);
      setLastFailedAction && setLastFailedAction({ type: 'apres', message: msg });
      toast.error(msg);
      return;
    }
    setApresLoading(true);
    setApresCriticalError(null);
    setApresLogs([]);
    setApresCompleted(false);
    setApresData(null);
    setComparisonResults(null);
    try {
      const apresPayload = {
        ident_data: sessionData.ident_data,
        password: credentials.password,
      };
      const response = await runApresChecks(apresPayload);
      setApresLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setApresData(response.data.structured_data);
        setComparisonResults(response.data.comparison_result);
        setApresCriticalError(null);
        setApresCompleted(true);
        toast.success("APRES checks and comparison completed successfully!");
      } else {
        const errMsg = response.data.message || 'APRES checks failed.';
        setApresCriticalError(errMsg);
        setApresCompleted(false);
        setApresData(null);
        setComparisonResults(null);
        setLastFailedAction && setLastFailedAction({ type: 'apres', message: errMsg });
        toast.error(`APRES Failed: ${errMsg}`);
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during APRES checks.';
      setApresCriticalError(errorMsg);
      setApresCompleted(false);
      setApresData(null);
      setComparisonResults(null);
      setApresLogs((prev) => [...prev, `Error: ${errorMsg}`]);
      setLastFailedAction && setLastFailedAction({ type: 'apres', message: errorMsg });
      toast.error(`APRES Error: ${errorMsg}`);
      if(err.response?.status === 401 || err.response?.status === 403) logout();
    } finally {
      setApresLoading(false);
    }
  }, [credentials, sessionData.ident_data, logout, setLastFailedAction]);

  // For manual triggering (reload)
  const handleReloadApres = useCallback(() => {
    setApresCriticalError(null);
    setApresCompleted(false);
    setApresData(null);
    setComparisonResults(null);
    setApresLogs([]);
    setApresLoading(true);
    fetchApresChecks();
  }, [fetchApresChecks]);

  // For compatibility with old API
  const handleApresProcessFinished = () => {};



  return {
    showApresConfirmModal,
    apresCriticalError,
    apresCompleted,
    apresData,
    comparisonResults,
    apresLogs,
    apresLoading,
    handleTriggerApres,
    handleConfirmApres,
    handleCancelApres,
    handleApresProcessFinished,
    handleReloadApres,
  };
};