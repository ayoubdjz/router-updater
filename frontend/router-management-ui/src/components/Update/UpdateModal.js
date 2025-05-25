import React, { useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress'; // Added for loading state

//isLoading prop added, but not directly used in this component's rendering yet.
//Parent (DashboardPage) handles disabling buttons/showing progress.
const UpdateModal = ({ open, onClose, onConfirm, isLoading }) => { 
  const [filename, setFilename] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (!filename.trim()) {
      setError('Please enter a valid filename');
      return;
    }
    setError('');
    onConfirm(filename.trim());
    // Parent will close the modal (setIsUpdateModalOpen(false))
    // and open the streaming log modal.
  };

  const handleCancel = () => {
    // setFilename(''); // Keep filename if user reopens, or clear if preferred
    // setError('');
    onClose();
  };
  
  // Clear filename and error when modal is opened (if desired)
  // This might be better handled by parent resetting state before opening
  React.useEffect(() => {
    if (open) {
      // setFilename(''); // Uncomment to always clear filename on open
      setError('');
    }
  }, [open]);


  return (
    <Dialog 
      open={open} 
      onClose={isLoading ? null : handleCancel} // Prevent closing if loading
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
            helperText="Example: jinstall-ppc-21.4R3.15-signed.tgz (must be in /var/tmp/ on router)"
            variant="outlined"
            placeholder="jinstall-ppc-21.4R3.15-signed.tgz"
            autoFocus
            disabled={isLoading}
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel} disabled={isLoading}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" color="primary" disabled={isLoading}>
          {isLoading ? <CircularProgress size={24} sx={{ color: 'white' }} /> : "Start Update"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default UpdateModal;