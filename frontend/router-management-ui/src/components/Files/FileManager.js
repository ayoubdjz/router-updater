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

const FileManager = () => {
  const [files, setFiles] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
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
      setError(err.response?.data?.message || err.message || 'Failed to fetch files.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleDelete = async (filename) => {
    if (window.confirm(`Are you sure you want to delete ${filename}?`)) {
      setIsLoading(true); // You might want a more granular loading state
      try {
        await deleteGeneratedFile(filename);
        fetchFiles(); // Refresh file list
      } catch (err) {
        setError(err.response?.data?.message || err.message || `Failed to delete ${filename}.`);
      } finally {
        setIsLoading(false);
      }
    }
  };

  const handleViewFile = async (filename) => {
    setIsLoading(true);
    setError('');
    setSelectedFileName(filename);
    try {
      const response = await getFileContent(filename);
      setSelectedFileContent(response.data); // Axios directly gives data for text responseType
      setIsFileViewerOpen(true);
    } catch (err) {
      setError(err.response?.data?.message || err.message || `Failed to fetch content for ${filename}.`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCloseFileViewer = () => {
    setIsFileViewerOpen(false);
    setSelectedFileContent('');
    setSelectedFileName('');
  };


  return (
    <Box>
      {isLoading && <CircularProgress sx={{ display: 'block', margin: 'auto' }} />}
      {error && <Alert severity="error">{error}</Alert>}
      <Button onClick={fetchFiles} variant="outlined" sx={{mb: 2}} disabled={isLoading}>Refresh File List</Button>
      <List>
        {files.length > 0 ? files.map((file) => (
          <Paper key={file} elevation={1} sx={{mb:1}}>
            <ListItem
              secondaryAction={
                <>
                  <IconButton edge="end" aria-label="view" onClick={() => handleViewFile(file)} disabled={isLoading}>
                    <VisibilityIcon />
                  </IconButton>
                  <IconButton edge="end" aria-label="delete" onClick={() => handleDelete(file)} disabled={isLoading}>
                    <DeleteIcon />
                  </IconButton>
                </>
              }
            >
              <ListItemText primary={file} />
            </ListItem>
          </Paper>
        )) : (
          !isLoading && <Typography>No files found in generated_files directory.</Typography>
        )}
      </List>

      <Dialog open={isFileViewerOpen} onClose={handleCloseFileViewer} maxWidth="md" fullWidth>
        <DialogTitle>Viewing: {selectedFileName}</DialogTitle>
        <DialogContent>
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