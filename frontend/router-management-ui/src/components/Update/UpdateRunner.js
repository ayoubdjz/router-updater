import React, { useState } from 'react';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';
import { toast } from 'react-toastify'; // <<<--- ADDED
import { useAuth } from '../../contexts/AuthContext';
import { runUpdateProcedure } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';

const UpdateRunner = ({ onUpdateProcessFinished }) => { 
  const { credentials, sessionData, updateSession, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [imageFile, setImageFile] = useState(sessionData.lastImageFile || '');
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);
  const [updateRunData, setUpdateRunData] = useState(null);

  const handleRunUpdate = async () => {
    if (!credentials || !sessionData.ident_data) {
      const msg = "Authentication or AVANT session data missing. Cannot proceed with update.";
      setError(msg);
      toast.error(msg);
      return;
    }
    if (!imageFile.trim()) {
      const msg = "Software image file name (on router) is required.";
      setError(msg);
      toast.warn(msg);
      return;
    }

    setIsLoading(true);
    setError('');
    setLogs([]);
    setUpdateRunData(null);
    toast.info(`Starting software update with image: ${imageFile.trim()}. This may take a long time...`);

    const updatePayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password,
      image_file: imageFile.trim(),
    };

    let updateSuccess = false;
    try {
      const response = await runUpdateProcedure(updatePayload);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setUpdateRunData(response.data);
        updateSession({ 
          updateCompleted: true, 
          updateData: response.data.updated_junos_info || null,
          lastImageFile: imageFile.trim()
        });
        setError('');
        updateSuccess = true;
        toast.success("Software update process reported success!");
      } else {
        const errMsg = response.data.message || 'Update procedure failed.';
        setError(errMsg);
        toast.error(`Update Failed: ${errMsg}`);
        updateSession({ updateCompleted: false }); 
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during update.';
      setError(errorMsg);
      toast.error(`Update Error: ${errorMsg}`);
      const errLogs = err.response?.data?.logs || [];
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...errLogs]);
      updateSession({ updateCompleted: false });
      if(err.response?.status === 401 || err.response?.status === 403) {
        logout();
      }
    } finally {
      setIsLoading(false);
      if (onUpdateProcessFinished) onUpdateProcessFinished(updateSuccess); 
    }
  };
  
  if (!sessionData.avantCompleted || !sessionData.updateAttempted || sessionData.updateCompleted) {
    return null;
  }

  return (
    <Paper elevation={2} sx={{ my: 2, p: 3, backgroundColor: isLoading ? '#e0e0e0' : '#fff9c4' }}>
      <Typography variant="h5" gutterBottom>Step 2: Software Update Configuration</Typography>
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

      {sessionData.updateCompleted && updateRunData?.status === 'success' && (
         <Box sx={{my:2}}>
            <Alert severity="success" icon={false}>Update procedure completed successfully!</Alert>
            {updateRunData.updated_junos_info && (
                <Typography variant="body2" sx={{mt:1}}>
                    New Junos Version (reported): {updateRunData.updated_junos_info.new_junos_version}
                </Typography>
            )}
        </Box>
      )}
       {updateRunData && updateRunData.status !== 'success' && !isLoading && ( 
          <Alert severity="warning" sx={{my:1}}>
            The update process encountered an issue. You can review logs and decide to run APRES checks or reset.
          </Alert>
        )}
    </Paper>
  );
};

export default UpdateRunner;