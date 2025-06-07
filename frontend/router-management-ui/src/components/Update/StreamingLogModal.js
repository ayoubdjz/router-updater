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
    if (finalStatus.status === 'success') {
      statusSeverity = "success";
      statusMessage = finalStatus.message || "Operation completed successfully.";
    } else if (finalStatus.status === 'success_with_warning') {
      statusSeverity = "warning";
      statusMessage = finalStatus.message || "Operation completed with warnings.";
    } else if (finalStatus.status === 'error') {
      statusSeverity = "error";
      statusMessage = finalStatus.message || "An error occurred.";
    } else if (finalStatus.status === 'warning') {
      statusSeverity = "warning";
      statusMessage = finalStatus.message || "Operation ended with a warning.";
    } else if (finalStatus.status === 'info') {
      statusSeverity = "info";
      statusMessage = finalStatus.message || "Operation status info.";
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
  } else if (!isLoading) {
    statusSeverity = "error";
    statusMessage = "Update failed or was cancelled.";
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
            <Typography>Processing... please wait.</Typography>
          </Box>
        )}

        {finalStatus && (
          <Alert severity={statusSeverity} sx={{mt: 1}}>
            {statusMessage}
            {finalStatus.updated_junos_info && (
                <Typography variant="body2" sx={{mt:1}}>
                    New JUNOS Version: {finalStatus.updated_junos_info.new_junos_version || 'N/A'} <br/>
                    Current Master RE: {finalStatus.updated_junos_info.current_master_re !== undefined ? `RE${finalStatus.updated_junos_info.current_master_re}` : 'N/A'}
                </Typography>
            )}
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