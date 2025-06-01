import React from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import StructuredDataDisplay from '../Common/StructuredDataDisplay';
import GeneratedFilesSection from './GeneratedFilesSection'; // Import GeneratedFilesSection
import { useAuth } from '../../contexts/AuthContext'; // To get sessionData.avantData

const AvantSection = ({
  isAvantLoading,
  handleReloadAvant,
  setShowAvantLogsModal, // To open the full logs modal
  // Generated Files Props
  generatedFilesProps
}) => {
  const { sessionData } = useAuth();

  return (
    <Paper elevation={2} sx={{ p: { xs: 2, md: 3 }, mb: 3, backgroundColor: 'hsl(207, 73%, 94%)' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
        <Typography variant="h5">Pre-Check Information</Typography>
        <Button variant="outlined" color="secondary" onClick={handleReloadAvant} disabled={isAvantLoading || sessionData.updateInProgress}>
          {isAvantLoading ? <CircularProgress size={20} sx={{ mr: 1 }} /> : null} Reload Pre-Checks
        </Button>
      </Box>
      
      <StructuredDataDisplay data={sessionData.avantData} titlePrefix="AVANT" />
      
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2, gap: 2, flexWrap: 'wrap' }}>
        <Button variant="outlined" onClick={() => setShowAvantLogsModal(true)}>Show Pre-Checks Logs</Button>
      </Box>
      {/* Render GeneratedFilesSection here */}
      <GeneratedFilesSection {...generatedFilesProps} />
    </Paper>
  );
};

export default AvantSection;