import React, { useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';

const UpdateModal = ({ open, onClose, onConfirm }) => {
  const [filename, setFilename] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (!filename.trim()) {
      setError('Please enter a valid filename');
      return;
    }
    setError('');
    onConfirm(filename.trim());
    // Do NOT call onClose here; let parent close the modal after processing if needed
  };

  const handleCancel = () => {
    setFilename('');
    setError('');
    onClose();
  };

  return (
    <Dialog 
      open={open} 
      onClose={handleCancel}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Software Update</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <TextField
            fullWidth
            label="Software Update Filename"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            helperText="Example: jinstall-ppc-21.4R3.15-signed.tgz (do not include a path)"
            variant="outlined"
            placeholder="jinstall-ppc-21.4R3.15-signed.tgz"
            autoFocus
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" color="primary">
          Run Update
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default UpdateModal;
