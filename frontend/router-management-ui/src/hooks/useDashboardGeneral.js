import { useState, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { unlockRouter } from '../api/routerApi';
import { toast } from 'react-toastify';

export const useDashboardGeneral = () => {
  const { sessionData, resetWorkflow } = useAuth();
  const [isActionLoading, setIsActionLoading] = useState(false); // For general actions like unlock
  const [actionError, setActionError] = useState(''); // General error message display
  const [dashboardActionLogs, setDashboardActionLogs] = useState([]);
  const [lastFailedAction, setLastFailedAction] = useState(null); // { type: 'avant' | 'update' | 'apres', message: string }

  const handleForceUnlockAndFullReset = useCallback(async () => {
    if (!sessionData.lock_file_path) {
      const msg = "No lock file path known to attempt unlock.";
      toast.warn(msg); 
      setActionError(msg); 
      return;
    }
    setIsActionLoading(true); 
    setActionError(''); 
    setDashboardActionLogs(prev => [`Attempting force unlock for: ${sessionData.lock_file_path}`, ...prev]);
    try {
      const unlockResponse = await unlockRouter(sessionData.lock_file_path);
      const unlockMsg = `Force Unlock: ${unlockResponse.data.message || 'Unlock attempted.'}`;
      setDashboardActionLogs(prev => [unlockMsg, ...(unlockResponse.data.logs || []), ...prev]);
      toast.info(unlockMsg);
      resetWorkflow(); 
      // After resetWorkflow, AVANT checks should re-trigger if DashboardPage logic is correct
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'Failed to force unlock router.';
      setActionError(errorMsg); 
      toast.error(errorMsg);
      setDashboardActionLogs(prevLogs => [`Error during force unlock: ${errorMsg}`, ...prevLogs]);
    } finally {
      setIsActionLoading(false);
    }
  }, [sessionData.lock_file_path, resetWorkflow]);

  // setLastFailedAction will be returned for other hooks to call
  // handleRetry will be in DashboardPage.js to coordinate calls to specific retry fns from other hooks

  return {
    isActionLoading, // For general buttons like Force Unlock
    actionError, // For displaying general errors
    setActionError,
    dashboardActionLogs,
    setDashboardActionLogs,
    lastFailedAction,
    setLastFailedAction,
    handleForceUnlockAndFullReset,
  };
};