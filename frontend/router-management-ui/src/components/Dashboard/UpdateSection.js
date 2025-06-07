import React from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { useAuth } from '../../contexts/AuthContext'; // To get sessionData

const UpdateSection = ({
  handleOpenUpdateModal,
  isUpdateInProgressHook, // Renamed to avoid conflict with sessionData.updateInProgress
  updateOperationResult,
  retryUpdate, // Function to retry the update
  // updateImageFilename, // Needed if retry is very specific
}) => {
  const { sessionData } = useAuth(); // sessionData.updateInProgress, sessionData.updateCompleted

  return (
    <>
      {/* Software Update Button */}
      {!sessionData.updateInProgress && !sessionData.updateCompleted && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 2, py:1, borderBottom: '1px solid #e0e0e0', borderTop: '1px solid #e0e0e0' }}>
          <Button 
            variant="contained" 
            color="primary" 
            onClick={handleOpenUpdateModal}
            disabled={isUpdateInProgressHook} // Use the hook's state for button disable
          >
            {isUpdateInProgressHook ? <CircularProgress size={24} sx={{mr:1}} /> : null}
            Start Software Update
          </Button>
        </Box>
      )}

      {/* Show update status based on sessionData */}
      {sessionData.updateInProgress && (
        <Alert severity="info" sx={{ my: 2 }}>Software update in progress...</Alert>
      )}
      {sessionData.updateCompleted && updateOperationResult && (
        <Alert severity={updateOperationResult.status === 'success' ? 'success' : updateOperationResult.status === 'success_with_warning' ? 'warning' : 'error'} sx={{ my: 2 }}>
          Update Finished: {updateOperationResult.message}
          {updateOperationResult.status !== 'success' && updateOperationResult.status !== 'success_with_warning' && (
            <Button color="inherit" size="small" onClick={retryUpdate} sx={{ ml: 2 }}>RETRY UPDATE</Button>
          )}
        </Alert>
      )}
      {!sessionData.updateInProgress && !sessionData.updateCompleted && updateOperationResult && updateOperationResult.status === 'error' && (
        <Alert severity="error" sx={{ my: 2 }}>
          Update Failed: {updateOperationResult.message}
          <Button color="inherit" size="small" onClick={retryUpdate} sx={{ ml: 2 }}>RETRY UPDATE</Button>
        </Alert>
      )}
    </>
  );
};

export default UpdateSection;