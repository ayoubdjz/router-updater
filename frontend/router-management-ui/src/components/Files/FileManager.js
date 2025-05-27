import React, { useState } from 'react';
import { listGeneratedFiles, getFileContent, deleteGeneratedFile } from '../../api/routerApi';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton'; // For better accessibility
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import DeleteIcon from '@mui/icons-material/Delete';
import VisibilityIcon from '@mui/icons-material/Visibility';
import RefreshIcon from '@mui/icons-material/Refresh';
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
import { toast } from 'react-toastify';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'; // <<<--- ADDED

const FileManager = () => {
  const queryClient = useQueryClient(); // For invalidating queries

  // For viewing file content
  const [selectedFileContent, setSelectedFileContent] = useState('');
  const [isFileViewerOpen, setIsFileViewerOpen] = useState(false);
  const [selectedFileNameForView, setSelectedFileNameForView] = useState('');
  
  // React Query for listing files
  const { data: filesData, isLoading: isLoadingFiles, error: filesError, refetch: refetchFiles } = useQuery({
    queryKey: ['generatedFiles'], // Unique key for this query
    queryFn: async () => {
        const response = await listGeneratedFiles();
        return response.data.files || []; // Assuming API returns { files: [...] }
    },
    // staleTime: 1000 * 60, // 1 minute, optional
  });

  // React Query for fetching file content (triggered on demand)
  const viewFileMutation = useMutation({
    mutationFn: getFileContent, // API function expects filename
    onSuccess: (response, filename) => { // response is Axios response
      console.log(`Fetched content for ${filename}:`, response.data);
      setSelectedFileContent(response.data); // .data from axios if API returns text directly
      setSelectedFileNameForView(filename);
      setIsFileViewerOpen(true);
    },
    onError: (error, filename) => {
      toast.error(`Failed to fetch content for ${filename}: ${error.response?.data?.message || error.message}`);
    }
  });

  // React Query for deleting a file
  const deleteFileMutation = useMutation({
    mutationFn: deleteGeneratedFile, // API function expects filename
    onSuccess: (response, filename) => {
      toast.success(response.data.message || `File ${filename} deleted successfully!`);
      queryClient.invalidateQueries({ queryKey: ['generatedFiles'] }); // Refetch file list
    },
    onError: (error, filename) => {
      toast.error(error.response?.data?.message || `Failed to delete ${filename}.`);
    }
  });

  const handleDelete = (filename) => {
    if (window.confirm(`Are you sure you want to delete ${filename}?`)) {
      deleteFileMutation.mutate(filename);
    }
  };

  const handleViewFile = (filename) => {
    viewFileMutation.mutate(filename);
  };

  const handleCloseFileViewer = () => {
    setIsFileViewerOpen(false);
    setSelectedFileContent('');
    setSelectedFileNameForView('');
  };

  return (
    <Box>
      <Button 
        onClick={() => refetchFiles()} 
        variant="outlined" 
        sx={{mb: 2}} 
        disabled={isLoadingFiles || deleteFileMutation.isPending || viewFileMutation.isPending}
        startIcon={isLoadingFiles ? <CircularProgress size={16} /> : <RefreshIcon />}
      >
        Refresh File List
      </Button>

      {isLoadingFiles && <CircularProgress sx={{ display: 'block', margin: 'auto', my:2 }} />}
      {filesError && <Alert severity="error" sx={{my:1}}>{filesError.message}</Alert>}
      
      {!isLoadingFiles && filesData && (
        <List>
          {filesData.length > 0 ? filesData.map((file) => (
            <Paper key={file} elevation={1} sx={{mb:1}}>
              <ListItem
                secondaryAction={
                  <Box>
                    <IconButton 
                        edge="end" aria-label="view" 
                        onClick={() => handleViewFile(file)} 
                        disabled={deleteFileMutation.isPending || viewFileMutation.isPending || viewFileMutation.variables === file && viewFileMutation.isPending}
                    >
                      {viewFileMutation.isPending && viewFileMutation.variables === file ? <CircularProgress size={20} /> : <VisibilityIcon />}
                    </IconButton>
                    <IconButton 
                        edge="end" aria-label="delete" 
                        onClick={() => handleDelete(file)} 
                        disabled={deleteFileMutation.isPending || viewFileMutation.isPending || deleteFileMutation.variables === file && deleteFileMutation.isPending}
                    >
                       {deleteFileMutation.isPending && deleteFileMutation.variables === file ? <CircularProgress size={20} /> : <DeleteIcon />}
                    </IconButton>
                  </Box>
                }
              >
                <ListItemButton onClick={() => handleViewFile(file)} dense> {/* Make text clickable too */}
                    <ListItemText primary={file} />
                </ListItemButton>
              </ListItem>
            </Paper>
          )) : (
            <Typography sx={{fontStyle:'italic'}}>No files found in generated_files directory.</Typography>
          )}
        </List>
      )}

      <Dialog open={isFileViewerOpen} onClose={handleCloseFileViewer} maxWidth="md" fullWidth scroll="paper">
        <DialogTitle>Viewing: {selectedFileNameForView}</DialogTitle>
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