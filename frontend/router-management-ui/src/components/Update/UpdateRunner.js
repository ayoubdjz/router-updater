import React, { useState } from 'react';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import { toast } from 'react-toastify';
import { useAuth } from '../../contexts/AuthContext';
import { runUpdateProcedure } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';
import { useMutation } from '@tanstack/react-query'; // <<<--- ADDED

const UpdateRunner = ({ onUpdateProcessFinished }) => { 
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [imageFile, setImageFile] = useState(sessionData.lastImageFile || '');
  // Local error/logs for this specific run attempt, React Query handles overall mutation state
  const [currentRunError, setCurrentRunError] = useState('');
  const [currentRunLogs, setCurrentRunLogs] = useState([]);

  const updateMutation = useMutation({
    mutationFn: runUpdateProcedure, // API func expects { ident_data, password, image_file }
    onSuccess: (response) => {
      const data = response.data;
      setCurrentRunLogs(data.logs || []);
      updateSession({ 
        updateCompleted: true, 
        updateData: data.updated_junos_info || null,
        lastImageFile: imageFile.trim()
      });
      toast.success("Software update process reported success!");
      if (onUpdateProcessFinished) onUpdateProcessFinished(true); // Signal success
    },
    onError: (error) => {
      const errorMsg = error.response?.data?.message || error.message || 'Update procedure failed.';
      setCurrentRunError(errorMsg);
      toast.error(`Update Failed: ${errorMsg}`);
      setCurrentRunLogs(error.response?.data?.logs || [errorMsg]);
      updateSession({ updateCompleted: false }); // Mark as not completed on failure
      if (onUpdateProcessFinished) onUpdateProcessFinished(false); // Signal failure
      if(error.response?.status === 401 || error.response?.status === 403) {
        logout();
      }
    },
  });

  const handleRunUpdate = () => {
    if (!credentials || !sessionData.ident_data) {
      const msg = "Authentication or AVANT session data missing.";
      setCurrentRunError(msg); toast.error(msg); return;
    }
    if (!imageFile.trim()) {
      const msg = "Software image file name (on router) is required.";
      setCurrentRunError(msg); toast.warn(msg); return;
    }
    setCurrentRunError(''); setCurrentRunLogs([]);
    toast.info(`Starting software update with image: ${imageFile.trim()}. This may take a long time...`);
    updateMutation.mutate({
      ident_data: sessionData.ident_data,
      password: credentials.password,
      image_file: imageFile.trim(),
    });
  };
  
  if (!sessionData.avantCompleted || !sessionData.updateAttempted || sessionData.updateCompleted) {
    return null;
  }

  return (
    <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: updateMutation.isPending ? '#e0e0e0' : '#fff9c4' }}>
      <Typography variant="h5" gutterBottom>Step 2: Software Update Configuration</Typography>
      {(currentRunError || updateMutation.isError) && (
        <Alert severity="error" sx={{my:1}}>
            {currentRunError || updateMutation.error?.response?.data?.message || updateMutation.error?.message}
        </Alert>
      )}
      <TextField
        label="Software Image File Name (on router's /var/tmp/)"
        variant="outlined" fullWidth value={imageFile}
        onChange={(e) => setImageFile(e.target.value)}
        sx={{ my: 2 }}
        disabled={updateMutation.isPending || sessionData.updateCompleted}
        helperText="Example: jinstall-ppc-VERSION-signed.tgz"
      />
      <Button
        variant="contained" color="secondary" onClick={handleRunUpdate}
        disabled={updateMutation.isPending || !imageFile.trim() || sessionData.updateCompleted}
      >
        {updateMutation.isPending ? <CircularProgress size={24} sx={{color: 'white'}} /> : 'Run Software Update'}
      </Button>

      <LogDisplay logs={currentRunLogs} title="Update Execution Logs" />

      {sessionData.updateCompleted && updateMutation.data?.data?.status === 'success' && (
         <Box sx={{my:2}}>
            <Alert severity="success" icon={false}>Update procedure completed successfully!</Alert>
            {sessionData.updateData?.new_junos_version && (
                <Typography variant="body2" sx={{mt:1}}>
                    New Junos Version (reported): {sessionData.updateData.new_junos_version}
                </Typography>
            )}
        </Box>
      )}
       {updateMutation.isSuccess && updateMutation.data?.data?.status !== 'success' && !updateMutation.isPending && ( 
          <Alert severity="warning" sx={{my:1}}>
            The update process completed but reported issues. Review logs and proceed to APRES if desired.
          </Alert>
        )}
    </Paper>
  );
};

export default UpdateRunner;