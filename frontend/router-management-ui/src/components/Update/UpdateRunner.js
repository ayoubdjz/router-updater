import React, { useState } from 'react';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import { useAuth } from '../../contexts/AuthContext';
import { runUpdateProcedure } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
// Note: File upload UI is not included here, assuming image_file is a name on the router.

const UpdateRunner = ({ onUpdateComplete }) => { // onUpdateComplete to notify DashboardPage
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [imageFile, setImageFile] = useState(sessionData.lastImageFile || ''); // Persist imageFile name in session if needed
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);
  const [updateRunData, setUpdateRunData] = useState(null);

  const handleRunUpdate = async () => {
    if (!credentials || !sessionData.ident_data) {
      setError("Authentication or AVANT session data missing. Cannot proceed with update.");
      return;
    }
    if (!imageFile.trim()) {
      setError("Software image file name (on router) is required.");
      return;
    }

    setIsLoading(true);
    setError('');
    setLogs([]);
    setUpdateRunData(null);
    updateSession({ updateCompleted: false, updateData: null }); // Reset before run

    const updatePayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password,
      image_file: imageFile.trim(),
    };

    try {
      const response = await runUpdateProcedure(updatePayload);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setUpdateRunData(response.data);
        updateSession({ 
          updateCompleted: true, 
          updateData: response.data.updated_junos_info || null, // Store any structured data from update
          lastImageFile: imageFile.trim() // Store for convenience
        });
        setError('');
        if (onUpdateComplete) onUpdateComplete(true);
      } else {
        setError(response.data.message || 'Update procedure failed.');
        if (onUpdateComplete) onUpdateComplete(false);
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during update.';
      setError(errorMsg);
      const errLogs = err.response?.data?.logs || [];
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
      if (onUpdateComplete) onUpdateComplete(false);
      if(err.response?.status === 401 || err.response?.status === 403) {
        logout();
      }
    } finally {
      setIsLoading(false);
    }
  };
  
  // Do not render if AVANT hasn't completed or if update is already done.
  if (!sessionData.avantCompleted || sessionData.updateCompleted) return null;

  return (
    <Paper elevation={2} sx={{ my: 2, p: 3 }}>
      <Typography variant="h5" gutterBottom>Step 2: Software Update</Typography>
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <TextField
        label="Software Image File Name (on router's /var/tmp/)"
        variant="outlined"
        fullWidth
        value={imageFile}
        onChange={(e) => setImageFile(e.target.value)}
        sx={{ my: 2 }}
        disabled={isLoading || sessionData.updateCompleted}
        helperText="Example: jinstall-ppc-VERSION-signed.tgz"
      />
      <Button
        variant="contained"
        color="secondary"
        onClick={handleRunUpdate}
        disabled={isLoading || !imageFile.trim() || !sessionData.avantCompleted || sessionData.updateCompleted}
      >
        {isLoading ? <CircularProgress size={24} sx={{color: 'white'}} /> : 'Run Software Update'}
      </Button>

      <LogDisplay logs={logs} title="Update Execution Logs" />

      {sessionData.updateCompleted && updateRunData && updateRunData.status === 'success' && (
         <Box sx={{my:2}}>
            <Alert severity="success" icon={false}>Update procedure completed successfully!</Alert>
            {updateRunData.updated_junos_info && (
                <Typography variant="body2" sx={{mt:1}}>
                    New Junos Version (reported): {updateRunData.updated_junos_info.new_junos_version}
                </Typography>
            )}
        </Box>
      )}
    </Paper>
  );
};

export default UpdateRunner;