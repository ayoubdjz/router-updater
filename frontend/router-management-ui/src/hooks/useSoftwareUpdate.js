import { useState, useCallback, useRef, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { runUpdateProcedureStream } from '../api/routerApi';
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

    if (abortControllerRef.current) {
        abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();
    const { signal } = abortControllerRef.current;

    try {
      const updateData = { image_file: currentFilename };
      await runUpdateProcedureStream(
        updateData,
        credentials,
        sessionData.ident_data,
        (logLine) => setStreamingUpdateLogs((prev) => [...prev, logLine]),
        (result) => {
          setUpdateOperationResult(result);
          // Determine update status based on result.status
          if (result && (result.status === 'success' || result.status === 'ok')) {
            updateSession({ updateCompleted: true, updateInProgress: false });
            setIsUpdateInProgress(false);
            toast.success(result.message || "Mise à jour terminé avec succès.");
          } else {
            updateSession({ updateCompleted: false, updateInProgress: false });
            setIsUpdateInProgress(false);
            toast.error(result.message || result.error || "Erreur lors de la mise à jour.");
          }
        },
        (err) => {
          const errorMsg = `Failed to run update: ${err.message}`;
          setUpdateOperationResult({ status: 'error', message: errorMsg });
          setLastFailedAction({ type: 'update', message: errorMsg });
          toast.error(errorMsg);
          updateSession({ updateCompleted: false, updateInProgress: false });
          setIsUpdateInProgress(false);
        },
        signal
      );
    } catch (err) {
      const errorMsg = `Failed to run update: ${err.message}`;
      setUpdateOperationResult({ status: 'error', message: errorMsg });
      setLastFailedAction({ type: 'update', message: errorMsg });
      toast.error(errorMsg);
      updateSession({ updateCompleted: false, updateInProgress: false });
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