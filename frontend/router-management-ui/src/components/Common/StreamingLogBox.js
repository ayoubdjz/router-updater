import React from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import CircularProgress from '@mui/material/CircularProgress';

const StreamingLogBox = ({
  open, // not used, for modal compatibility
  onClose, // not used, for modal compatibility
  logs = [],
  title = 'Logs',
  isLoading = false,
  finalStatus = null,
  actions = null, // optional extra actions (e.g., retry button)
  height = 300,
  maxHeight = 400,
  minHeight = 200,
  sx = {},
}) => {
  return (
    <Box
      sx={{
        bgcolor: '#222',
        color: '#fff',
        p: 2,
        minHeight,
        maxHeight,
        height,
        overflowY: 'auto',
        fontFamily: 'monospace',
        borderRadius: 2,
        boxShadow: 2,
        ...sx,
      }}
    >
      <Typography variant="subtitle1" sx={{ mb: 1, color: '#90caf9', fontWeight: 700 }}>{title}</Typography>
      {isLoading && (
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <CircularProgress size={18} sx={{ mr: 1, color: '#90caf9' }} />
          <Typography variant="body2">En cours...</Typography>
        </Box>
      )}
      <Box>
        {logs.length === 0 ? (
          <Typography variant="body2" sx={{ color: '#aaa' }}>Aucun log pour le moment.</Typography>
        ) : (
          logs.map((line, idx) => (
            <div key={idx}>{line}</div>
          ))
        )}
      </Box>
      {finalStatus && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="body2" sx={{ color: finalStatus.status === 'success' ? '#4caf50' : '#f44336' }}>
            {finalStatus.message}
          </Typography>
        </Box>
      )}
      {actions && (
        <Box sx={{ mt: 2 }}>{actions}</Box>
      )}
    </Box>
  );
};

export default StreamingLogBox;
