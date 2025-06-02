import { useState, useCallback, useRef, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { runUpdateProcedure } from '../api/routerApi';
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
      // Use runUpdateProcedure instead of fetch
      const updateData = { image_file: currentFilename };
      const response = await runUpdateProcedure(updateData, credentials, sessionData.ident_data);
      // Handle response (non-streaming, synchronous)
      if (response.data.status !== 'success') {
        throw new Error(response.data.message || 'Update failed.');
      }
      setUpdateOperationResult(response.data.result);
      setStreamingUpdateLogs(response.data.result?.logs || []);
      updateSession({ updateCompleted: true, updateInProgress: false });
      toast.success(response.data.result?.message || "Update completed successfully!");
    } catch (err) {
      const errorMsg = `Failed to run update: ${err.message}`;
      setUpdateOperationResult({ status: 'error', message: errorMsg });
      setLastFailedAction({ type: 'update', message: errorMsg });
      toast.error(errorMsg);
      updateSession({ updateCompleted: false, updateInProgress: false });
    } finally {
      setIsUpdateInProgress(false);
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