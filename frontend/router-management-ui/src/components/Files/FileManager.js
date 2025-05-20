import React, { useState, useEffect } from 'react';
import { listGeneratedFiles, getFileContent, deleteGeneratedFile } from '../../api/routerApi';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import DeleteIcon from '@mui/icons-material/Delete';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { toast } from 'react-toastify'; // <<<--- ADDED

const FileManager = () => {
  const [files, setFiles] = useState([]);
  const [isLoading, setIsLoading] = useState(false); // General loading for list
  const [isDeleting, setIsDeleting] = useState(null); // Specific file being deleted
  const [isViewing, setIsViewing] = useState(null); // Specific file being viewed
  const [error, setError] = useState('');
  const [selectedFileContent, setSelectedFileContent] = useState('');
  const [isFileViewerOpen, setIsFileViewerOpen] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState('');

  const fetchFiles = async () => {
    setIsLoading(true);
    setError('');
    try {
      const response = await listGeneratedFiles();
      setFiles(response.data.files || []);
    } catch (err) {
      const errMsg = err.response?.data?.message || err.message || 'Failed to fetch files.';
      setError(errMsg);
      toast.error(errMsg);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleDelete = async (filename) => {
    if (window.confirm(`Are you sure you want to delete ${filename}?`)) {
      setIsDeleting(filename);
      setError('');
      try {
        await deleteGeneratedFile(filename);
        toast.success(`File ${filename} deleted successfully!`);
        fetchFiles(); 
      } catch (err) {
        const errMsg = err.response?.data?.message || err.message || `Failed to delete ${filename}.`;
        setError(errMsg);
        toast.error(errMsg);
      } finally {
        setIsDeleting(null);
      }
    }
  };

  const handleViewFile = async (filename) => {
    setIsViewing(filename);
    setError('');
    setSelectedFileName(filename);
    try {
      const response = await getFileContent(filename);
      setSelectedFileContent(response.data); 
      setIsFileViewerOpen(true);
    } catch (err) {
      const errMsg = err.response?.data?.message || err.message || `Failed to fetch content for ${filename}.`;
      setError(errMsg);
      toast.error(errMsg);
    } finally {
      setIsViewing(null);
    }
  };

  const handleCloseFileViewer = () => {
    setIsFileViewerOpen(false);
    setSelectedFileContent('');
    setSelectedFileName('');
  };

  return (
    <Box>
      {isLoading && !isDeleting && !isViewing && <CircularProgress sx={{ display: 'block', margin: 'auto', my:2 }} />}
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <Button onClick={fetchFiles} variant="outlined" sx={{mb: 2}} disabled={isLoading || !!isDeleting || !!isViewing}>
        Refresh File List
      </Button>
      <List>
        {files.length > 0 ? files.map((file) => (
          <Paper key={file} elevation={1} sx={{mb:1}}>
            <ListItem
              secondaryAction={
                <Box>
                  <IconButton edge="end" aria-label="view" onClick={() => handleViewFile(file)} disabled={!!isDeleting || !!isViewing}>
                    {isViewing === file ? <CircularProgress size={20} /> : <VisibilityIcon />}
                  </IconButton>
                  <IconButton edge="end" aria-label="delete" onClick={() => handleDelete(file)} disabled={!!isDeleting || !!isViewing}>
                     {isDeleting === file ? <CircularProgress size={20} /> : <DeleteIcon />}
                  </IconButton>
                </Box>
              }
            >
              <ListItemText primary={file} />
            </ListItem>
          </Paper>
        )) : (
          !isLoading && <Typography sx={{fontStyle:'italic'}}>No files found in generated_files directory.</Typography>
        )}
      </List>

      <Dialog open={isFileViewerOpen} onClose={handleCloseFileViewer} maxWidth="md" fullWidth scroll="paper">
        <DialogTitle>Viewing: {selectedFileName}</DialogTitle>
        <DialogContent dividers>
          <Paper elevation={0} sx={{ p: 2, maxHeight: '70vh', overflow: 'auto', backgroundColor: '#f5f5f5' }}>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: '0.875rem' }}>
              {selectedFileContent}
            </pre>
          </Paper>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseFileViewer}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default FileManager;