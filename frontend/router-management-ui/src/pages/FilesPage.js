import React from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import FileManager from '../components/Files/FileManager'; // We will create this

const FilesPage = () => {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Manage Generated Files
      </Typography>
      <FileManager />
    </Box>
  );
};

export default FilesPage;