import React from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import AvantRunner from '../components/Avant/AvantRunner'; // We will create this

const DashboardPage = () => {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Router Operations Dashboard
      </Typography>
      <AvantRunner />
      {/* More components will go here for Update and Apres */}
    </Box>
  );
};

export default DashboardPage;