import { useState, useCallback, useRef, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { API_BASE_URL } from '../api/routerApi';
import { toast } from 'react-toastify';

export const useSoftwareUpdate = (setLastFailedAction) => {
  const { credentials, sessionData, updateSession } = useAuth();
  const [isUpdateModalOpen, setIsUpdateModalOpen] = useState(false);
  const [updateImageFilename, setUpdateImageFilename] = useState('');
  const [isStreamingLogModalOpen, setIsStreamingLogModalOpen] = useState(false);
  const [streamingUpdateLogs, setStreamingUpdateLogs] = useState([]);
  const [isUpdateInProgress, setIsUpdateInProgress] = useState(false);
  const [updateOperationResult, setUpdateOperationResult] = useState(null); // {status, message, data}
  
  const abortControllerRef = useRef(null);

  const handleOpenUpdateModal = () => setIsUpdateModalOpen(true);
  const handleCloseUpdateModal = () => {
    setIsUpdateModalOpen(false);
    setUpdateImageFilename('');
  };

  const handleStartUpdateProcedure = useCallback(async (imageFilenameFromModal) => {
    if (!credentials || !sessionData.ident_data) {
      toast.error("Cannot start update: Missing credentials or pre-check data.");
      return;
    }
    const currentFilename = imageFilenameFromModal || updateImageFilename;
    if (!currentFilename) {
        toast.error("Cannot start update: Image filename is missing.");
        setIsUpdateModalOpen(true); // Re-open if filename was lost
        return;
    }

    setUpdateImageFilename(currentFilename); // Ensure it's set for potential retries
    setIsUpdateModalOpen(false);
    setIsStreamingLogModalOpen(true);
    setIsUpdateInProgress(true);
    setStreamingUpdateLogs([]);
    setUpdateOperationResult(null);
    setLastFailedAction(null);
    updateSession({ updateAttempted: true, updateCompleted: false, updateInProgress: true });

    if (abortControllerRef.current) { // Abort previous if any
        abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();
    const { signal } = abortControllerRef.current;

    try {
      const response = await fetch(`${API_BASE_URL}/run_update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ident_data: sessionData.ident_data,
          password: credentials.password,
          image_file: currentFilename,
        }),
        signal,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: `HTTP error ${response.status}` }));
        throw new Error(errorData.message || `Server responded with ${response.status}`);
      }
      if (!response.body) throw new Error("Response body is null, cannot stream.");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (signal.aborted) { // Check if aborted by user closing modal elsewhere
            throw new Error('AbortError'); // Simulate AbortError to be caught
        }
        if (done) {
          if (!updateOperationResult) {
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
              const jsonData = JSON.parse(message.substring(5));
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
              const eventType = eventLine.substring(6).trim();
              try {
                const eventData = JSON.parse(dataLine.substring(5).trim());
                if (eventType === 'update_complete') {
                  setUpdateOperationResult(eventData);
                  updateSession({ updateCompleted: true, updateInProgress: false });
                  if (eventData.status === 'success') toast.success(eventData.message || "Update completed successfully!");
                  else if (eventData.status === 'success_with_warning') toast.warn(eventData.message || "Update completed with warnings.");
                  else toast.error(eventData.message || "Update finished with errors.");
                  reader.cancel(); return;
                } else if (eventType === 'update_error') {
                  setUpdateOperationResult(eventData);
                  updateSession({ updateCompleted: false, updateInProgress: false });
                  setLastFailedAction({ type: 'update', message: eventData.message });
                  toast.error(eventData.message || "A critical error occurred during the update stream.");
                  reader.cancel(); return;
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
        const errorMsg = `Failed to run update: ${err.message}`;
        setUpdateOperationResult({ status: 'error', message: errorMsg });
        setLastFailedAction({ type: 'update', message: errorMsg });
        toast.error(errorMsg);
      }
      updateSession({ updateCompleted: false, updateInProgress: false });
    } finally {
      setIsUpdateInProgress(false);
      if (abortControllerRef.current && !abortControllerRef.current.signal.aborted) {
          // If not aborted by user, but finished (success/error/unexpected), nullify ref
          // If aborted by user, it's already handled.
      }
      // Don't nullify abortControllerRef.current here if we want to allow retry.
      // It will be overwritten on next call.
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credentials, sessionData.ident_data, updateSession, setLastFailedAction, updateImageFilename]);

  const handleCloseStreamingLogModal = () => {
    setIsStreamingLogModalOpen(false);
    if (isUpdateInProgress && abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  // Cleanup effect for abort controller
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const retryUpdate = () => {
    if (updateImageFilename) {
        handleStartUpdateProcedure(updateImageFilename);
    } else {
        toast.warn("Cannot retry update: Image filename not available. Please start the update process again.");
        setIsUpdateModalOpen(true);
    }
  };

  return {
    isUpdateModalOpen,
    updateImageFilename, // Expose for retry if needed
    isStreamingLogModalOpen,
    streamingUpdateLogs,
    isUpdateInProgress,
    updateOperationResult,
    handleOpenUpdateModal,
    handleCloseUpdateModal,
    handleStartUpdateProcedure,
    handleCloseStreamingLogModal,
    retryUpdate,
    setUpdateImageFilename, // Allow DashboardPage to set it if needed (e.g. from modal)
  };
};