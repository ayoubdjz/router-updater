import React, { useState } from 'react';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import { useAuth } from '../../contexts/AuthContext';
import { runUpdateProcedure } from '../../api/routerApi';
import LogDisplay from '../Common/LogDisplay';

const UpdateRunner = () => {
  const { credentials, sessionData, updateSessionData } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [imageFile, setImageFile] = useState('');
  const [updateResult, setUpdateResult] = useState(null);
  const [error, setError] = useState('');
  const [logs, setLogs] = useState([]);

  const handleRunUpdate = async () => {
    if (!credentials || !sessionData.ident_data) {
      setError("Authentication or session data missing.");
      return;
    }
    if (!imageFile.trim()) {
      setError("Software image file name is required.");
      return;
    }

    setIsLoading(true);
    setError('');
    setLogs([]);
    setUpdateResult(null);

    const updatePayload = {
      ident_data: sessionData.ident_data,
      password: credentials.password, // Make sure password is in credentials
      image_file: imageFile.trim(),
    };

    try {
      const response = await runUpdateProcedure(updatePayload);
      setLogs(response.data.logs || []);
      if (response.data.status === 'success') {
        setUpdateResult(response.data);
        updateSessionData({ 
          updateCompleted: true,
          // ident_data might be returned if changed, update if necessary
          // ident_data: response.data.ident_data || sessionData.ident_data 
        });
        setError('');
      } else {
        setError(response.data.message || 'Update procedure failed.');
        updateSessionData({ updateCompleted: false });
      }
    } catch (err) {
      const errorMsg = err.response?.data?.message || err.message || 'An error occurred during update.';
      setError(errorMsg);
      setLogs(prevLogs => [...prevLogs, `Error: ${errorMsg}`, ...(err.response?.data?.logs || [])]);
      updateSessionData({ updateCompleted: false });
    } finally {
      setIsLoading(false);
    }
  };

  if (!sessionData.avantCompleted) return null; // Only show if AVANT is done

  return (
    <Box sx={{ my: 2, p: 2, border: '1px solid lightgray', borderRadius: 1 }}>
      <Typography variant="h5">2. Software Update</Typography>
      {error && <Alert severity="error" sx={{my:1}}>{error}</Alert>}
      <TextField
        label="Software Image File Name (e.g., jinstall-ppc-VERSION-signed.tgz)"
        variant="outlined"
        fullWidth
        value={imageFile}
        onChange={(e) => setImageFile(e.target.value)}
        sx={{ my: 1 }}
        disabled={isLoading || sessionData.updateCompleted}
      />
      <Button
        variant="contained"
        onClick={handleRunUpdate}
        disabled={isLoading || !imageFile.trim() || sessionData.updateCompleted}
        sx={{my:1}}
      >
        {isLoading ? <CircularProgress size={24} /> : 'Run Software Update'}
      </Button>

      <LogDisplay logs={logs} title="Update Execution Logs" />

      {updateResult && updateResult.status === 'success' && (
        <Alert severity="success" sx={{my:1}}>Update procedure completed successfully!</Alert>
      )}
    </Box>
  );
};

export default UpdateRunner;