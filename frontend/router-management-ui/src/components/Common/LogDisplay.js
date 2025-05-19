import React from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Box from '@mui/material/Box';

const LogDisplay = ({ logs, title = "Logs" }) => {
  if (!logs || logs.length === 0) {
    return null; // Don't render if no logs
  }

  return (
    <Box sx={{ mt: 2, mb: 2 }}>
      <Typography variant="h6" gutterBottom>{title}</Typography>
      <Paper elevation={2} sx={{ maxHeight: '300px', overflow: 'auto', p: 1, backgroundColor: '#f5f5f5' }}>
        <List dense>
          {logs.map((log, index) => (
            <ListItem key={index} disableGutters sx={{p:0}}>
              <ListItemText
                primaryTypographyProps={{ sx: { fontSize: '0.875rem', fontFamily: 'monospace' } }}
                primary={log}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );
};

export default LogDisplay;