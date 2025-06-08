import React, { useEffect, useRef } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import Paper from '@mui/material/Paper';

const StreamingLogModal = ({ open, onClose, logs, title, isLoading, finalStatus }) => {
  const logsEndRef = useRef(null);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(scrollToBottom, [logs]);

  // Determine status from isLoading, finalStatus, or sessionData
  let statusSeverity = "info";
  let statusMessage = "Operation in progress...";

  // Try to get update session state from window (since no prop is passed)
  let updateSessionState = null;
  try {
    // This assumes sessionData is attached to window by the app for debugging
    updateSessionState = window.__UPDATE_SESSION_STATE__;
  } catch {}

  if (finalStatus) {
    if (finalStatus.success === 'true') {
      statusSeverity = "success";
      statusMessage = finalStatus.message || "Update Operation completed successfully.";
    } else if (finalStatus.success === 'false') {
      statusSeverity = "error";
      statusMessage = `An error occurred during the update operation: ${finalStatus.error || 'Unknown error'}`;
    } else {
      statusSeverity = "error";
      statusMessage = `An error occurred during the update operation: ${finalStatus.error || 'Unknown error'}`;
    }
  } else if (updateSessionState) {
    if (updateSessionState.updateCompleted) {
      statusSeverity = "success";
      statusMessage = "Update completed.";
    } else if (updateSessionState.updateInProgress) {
      statusSeverity = "info";
      statusMessage = "Operation in progress...";
    } else {
      statusSeverity = "error";
      statusMessage = "Update failed or was cancelled.";
    }
  } else if (isLoading) {
    statusSeverity = "info";
    statusMessage = "Operation in progress...";
  }


  return (
    <Dialog open={open} onClose={isLoading ? null : onClose} maxWidth="md" fullWidth scroll="paper">
      <DialogTitle>{title || 'Streaming Logs'}</DialogTitle>
      <DialogContent dividers>
        <Paper elevation={0} sx={{ p: 2, maxHeight: '60vh', overflow: 'auto', backgroundColor: '#f0f0f0', mb: 2 }}>
          {logs.length === 0 && !isLoading && !finalStatus && (
            <Typography sx={{ fontStyle: 'italic', textAlign: 'center' }}>
              Waiting for logs...
            </Typography>
          )}
          {logs.map((log, index) => (
            <Typography key={index} component="pre" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '0.8rem', margin: 0, py: 0.25 }}>
              {log}
            </Typography>
          ))}
          <div ref={logsEndRef} />
        </Paper>
        
        {isLoading && !finalStatus && (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', my: 1 }}>
            <CircularProgress size={24} sx={{ mr: 1 }} />
            <Typography>{statusMessage}</Typography>
          </Box>
        )}

        {finalStatus && (
          <Alert severity={statusSeverity} sx={{mt: 1}}>
            {statusMessage}
          </Alert>
        )}

      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={isLoading && !finalStatus}>
            {isLoading && !finalStatus ? "Cancel Update (Abort)" : "Close"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default StreamingLogModal;