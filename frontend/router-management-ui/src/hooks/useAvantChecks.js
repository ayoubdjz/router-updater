import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { API_BASE_URL, runAvantChecks } from '../api/routerApi'; // Assuming API_BASE_URL is exported here
import { toast } from 'react-toastify';

export const useAvantChecks = (setLastFailedAction) => {
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [isAvantLoading, setIsAvantLoading] = useState(false);
  const [avantError, setAvantError] = useState(''); // Local errors during fetch
  const [avantLogs, setAvantLogs] = useState([]); // Full logs after completion
  const [avantCriticalError, setAvantCriticalError] = useState(null); // Critical error from API response

  const initialAvantFetchInProgressRef = useRef(false);

  const performAvantChecks = useCallback(async () => {
    if (!credentials) {
      toast.error("Credentials not available for AVANT checks.");
      // Potentially call logout or navigate to login if credentials are a hard requirement here
      return;
    }
    initialAvantFetchInProgressRef.current = true;
    setIsAvantLoading(true);
    setAvantError('');
    setAvantLogs([]);
    setAvantCriticalError(null);
    if (setLastFailedAction) setLastFailedAction(null);

    updateSession({
      ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
      avantCompleted: false, avantData: null,
      updateAttempted: false, updateCompleted: false, updateInProgress: false,
      apresCompleted: false, apresData: null, comparisonResults: null, 
      viewState: 'avant_loading'
    });

    try {
      // Synchronous, non-streaming API call
      const { data } = await runAvantChecks(credentials);
      setAvantLogs(data.logs || []);
      if (data.status === 'error') {
        console.error('AVANT checks failed:', data);
        setAvantError(data.message || 'AVANT checks failed.');
        setAvantCriticalError(data.message || 'AVANT checks failed.');
        updateSession({ avantCompleted: false, avantData: null, viewState: 'avant_error' });
        if (setLastFailedAction) setLastFailedAction({ type: 'avant', message: data.message || 'AVANT checks failed.' });
        toast.error(data.message || 'AVANT checks failed.');
        return;
      }
      updateSession({
        avantCompleted: true,
        avantData: data.structured_data || null,
        viewState: 'avant_completed',
        ident_data: data?.ident_data,
        lock_file_path: data?.lock_file_path,
        avant_file_path: data?.avant_file_path,
        config_file_path: data?.config_file_path,
      });
      toast.success(data.message || "AVANT checks completed successfully.");
    } catch (err) {
      // Improved error logging for network/server errors
      let errorMessage = 'Failed to perform AVANT pre-checks.';
      if (err.response && err.response.data) {
        console.error('AVANT API error:', err.response.data);
        errorMessage = err.response.data.message || JSON.stringify(err.response.data);
      } else {
        console.error('AVANT checks failed:', err);
        errorMessage = err.message || errorMessage;
      }
      setAvantError(errorMessage); 
      setAvantCriticalError(errorMessage); 
      updateSession({ avantCompleted: false, avantData: null, viewState: 'avant_error' });
      if (setLastFailedAction) setLastFailedAction({ type: 'avant', message: errorMessage });
      toast.error(errorMessage);
    } finally {
      setIsAvantLoading(false);
      initialAvantFetchInProgressRef.current = false;
    }
  }, [credentials, updateSession, setLastFailedAction, logout]);

  useEffect(() => {
    if (
      credentials &&
      !sessionData.avantCompleted && 
      !avantCriticalError &&          
      !isAvantLoading &&              
      !initialAvantFetchInProgressRef.current 
    ) {
      performAvantChecks();
    }
  }, [credentials, sessionData.avantCompleted, avantCriticalError, isAvantLoading]);

  const handleReloadAvant = useCallback(() => {
    setAvantCriticalError(null);
    setAvantError('');
    setAvantLogs([]);
    setIsAvantLoading(false); // Reset loading state
    initialAvantFetchInProgressRef.current = false; // Allow re-trigger
    // Reset relevant parts of session to allow performAvantChecks to run again via useEffect
    updateSession({
      ident_data: null, lock_file_path: null, avant_file_path: null, config_file_path: null,
      avantCompleted: false, avantData: null,
      viewState: 'initial' // Or 'avant_loading' to be more direct, but 'initial' + conditions in useEffect works
    });
    // The useEffect should pick up changes (e.g., avantCompleted: false) and re-run performAvantChecks.
  }, [updateSession]);


  return {
    isAvantLoading,
    avantLogs,
    avantCriticalError,
    setAvantCriticalError,
    handleReloadAvant,
    initialAvantFetchInProgressRef,
  };
};