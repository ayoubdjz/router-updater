import React from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button'; // For View AVANT File button
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import CircularProgress from '@mui/material/CircularProgress';
import IconButton from '@mui/material/IconButton';
import VisibilityIcon from '@mui/icons-material/Visibility';
// import DeleteIcon from '@mui/icons-material/Delete'; // Not used in provided snippet

const GeneratedFilesSection = ({
  generatedFiles,
  isLoadingFiles,
  fileAction,
  handleViewFile, // Require as prop, do not default to no-op
  // avantFileActionLoading, // For the main AVANT file view button - if it exists separately
  // handleDeleteFile, // Delete functionality was present in original DashboardPage
  // handleViewAvantFile, // For specific "View AVANT Report File" button
}) => {
  return (
    <>
      <Divider sx={{ my: 3 }}><Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#1976d2' }}>Generated Files</Typography></Divider>
      {/* Example: Button to view the main AVANT file report, if applicable
      {sessionData.avant_file_path && ( // This would need sessionData from useAuth or passed as prop
        <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
          <Button
            variant="contained"
            onClick={handleViewAvantFile}
            disabled={avantFileActionLoading}
            startIcon={avantFileActionLoading ? <CircularProgress size={18} /> : <VisibilityIcon />}
          >
            View AVANT Report File
          </Button>
        </Box>
      )}
      */}
      {isLoadingFiles ? <CircularProgress sx={{ display: 'block', margin: 'auto', my: 2 }} /> :
        generatedFiles.length === 0 ? (
          <Typography sx={{ fontStyle: 'italic', textAlign: 'center' }}>No additional files found.</Typography>
        ) : (
          <Grid container spacing={1.5}>
            {generatedFiles.map((file) => (
              <Grid item xs={12} sm={6} md={4} key={file}>
                <Paper elevation={1} sx={{ p: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Typography variant="body2" sx={{ wordBreak: 'break-all', mr:1, flexGrow: 1 }}>{file}</Typography>
                  <Box sx={{ display: 'flex', gap: 0.5, flexShrink: 0 }}>
                    <IconButton 
                        size="small" 
                        title={`View ${file}`} 
                        onClick={() => handleViewFile(file)} 
                        disabled={fileAction.type === 'view' && fileAction.filename === file}
                    >
                      {(fileAction.type === 'view' && fileAction.filename === file) ? <CircularProgress size={16} /> : <VisibilityIcon fontSize="small" />}
                    </IconButton>
                    {/* <IconButton 
                        size="small" 
                        title={`Delete ${file}`} 
                        onClick={() => handleDeleteFile(file)} 
                        disabled={fileAction.type === 'delete' && fileAction.filename === file}
                        color="error"
                    >
                      {(fileAction.type === 'delete' && fileAction.filename === file) ? <CircularProgress size={16} /> : <DeleteIcon fontSize="small" />}
                    </IconButton> */}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        )}
    </>
  );
};

export default GeneratedFilesSection;