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
  const [path, setPath] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (!path.trim()) {
      setError('Please enter a valid path');
      return;
    }
    onConfirm(path);
    onClose();
  };

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Software Update Configuration</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <TextField
            fullWidth
            label="Software Update Path"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            helperText="Enter the path to the software update file"
            variant="outlined"
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" color="primary">
          Run Update
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default UpdateModal;
