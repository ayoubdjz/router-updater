import { useState, useCallback, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { listGeneratedFiles, getFileContent, deleteGeneratedFile }/*, API_BASE_URL */ from '../api/routerApi';
import { toast } from 'react-toastify';

// If API_BASE_URL is needed for window.open, ensure it's available
// import { API_BASE_URL } from '../api/routerApi'; 

export const useGeneratedFiles = (avantCompleted, avantCriticalError) => {
  const { sessionData, updateSession } = useAuth();
  const [generatedFiles, setGeneratedFiles] = useState([]);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [fileAction, setFileAction] = useState({ type: null, filename: null }); // For loading state on individual file actions
  const [fileViewer, setFileViewer] = useState({ open: false, content: '', filename: '' });
  const [avantFileActionLoading, setAvantFileActionLoading] = useState(false);


  const fetchGeneratedFiles = useCallback(async () => {
    if (!avantCompleted || avantCriticalError) return;
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
  }, [avantCompleted, avantCriticalError]);

  useEffect(() => {
    fetchGeneratedFiles();
  }, [fetchGeneratedFiles]);

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
      // Update session if a known important file path is deleted
      if (sessionData.avant_file_path && filename === sessionData.avant_file_path.split(/[/\\]/).pop()) {
        updateSession({ avant_file_path: null, avantData: null }); // Might need to clear more if avantData depends on it
      }
      if (sessionData.config_file_path && filename === sessionData.config_file_path.split(/[/\\]/).pop()) {
        updateSession({ config_file_path: null });
      }
      if (sessionData.lock_file_path && filename === sessionData.lock_file_path.split(/[/\\]/).pop()) {
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

  // Specific handler for viewing the main AVANT file (e.g., opening in new tab)
  const handleViewAvantFile = useCallback(() => {
    if (!sessionData.avant_file_path) return;
    setAvantFileActionLoading(true);
    const fileName = sessionData.avant_file_path.split(/[/\\]/).pop();
    // Make sure API_BASE_URL is correctly prefixed if /api/files is relative in your setup
    window.open(`/api/files/${encodeURIComponent(fileName)}`, '_blank'); 
    setTimeout(() => setAvantFileActionLoading(false), 500); // Reset loading after a short delay
  }, [sessionData.avant_file_path]);


  return {
    generatedFiles,
    isLoadingFiles,
    fileAction, // To show loading on individual file buttons
    fileViewer,
    avantFileActionLoading,
    fetchGeneratedFiles,
    handleViewFile,
    handleDeleteFile,
    handleCloseFileViewer,
    handleViewAvantFile,
  };
};