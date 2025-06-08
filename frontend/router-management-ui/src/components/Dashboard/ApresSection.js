import React from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import StructuredDataDisplay from '../Common/StructuredDataDisplay';

import ComparisonModal from '../Common/ComparisonModal';

const ApresSection = ({
  apresCriticalError,
  apresCompleted,
  apresData,
  comparisonResults,
  apresLogs,
  apresLoading,
  handleTriggerApres,
  handleReloadApres,
  onShowLogs,
  onShowComparison,
  updateInProgress
}) => {

  if (apresCriticalError) {
    return (
      <Paper elevation={2} sx={{ p: 3, mb: 3, backgroundColor: 'hsl(0, 70%, 94%)', textAlign: 'center' }}>
        <Alert severity="error" sx={{ mb: 2 }}>Post-Checks Failed Critically: {apresCriticalError}</Alert>
        <Button variant="contained" color="primary" onClick={handleReloadApres}>Retry Post-Checks</Button>
      </Paper>
    );
  }

  return (
    <Paper elevation={2} sx={{ p: { xs: 2, md: 3 }, mb: 3, backgroundColor: 'hsl(207, 73%, 94%)' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
        <Typography variant="h5">Post-Checks Information</Typography>
        {(!apresLoading && !apresCompleted) && (
          <Button 
            variant="contained" 
            color="secondary" 
            onClick={handleTriggerApres} 
            disabled={updateInProgress}
          >
            Run Post-Checks
          </Button>
        )}
        {apresCompleted && (
          <Button 
            variant="outlined" 
            color="secondary" 
            onClick={handleReloadApres} 
            disabled={apresLoading || updateInProgress}
          >
            {apresLoading && <CircularProgress size={20} sx={{mr:1}}/>}
            Reload Post-Checks
          </Button>
        )}
      </Box>

      {/* Loading State */}
      {apresLoading && (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', my: 3 }}>
          <CircularProgress size={60} />
          <Typography variant="h6" sx={{ mt: 2 }}>Running APRES Post-Checks...</Typography>
          <Typography variant="body2">Please wait, this may take a few moments.</Typography>
        </Box>
      )}

      {/* Structured Data Display for APRES */}
      {apresCompleted && apresData && (
        <>
          <StructuredDataDisplay data={apresData} titlePrefix="APRES" />
          {/* Show comparison button if comparisonResults string exists */}
          {comparisonResults && typeof comparisonResults === 'string' && comparisonResults.trim().length > 0 && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
              <Button variant="outlined" onClick={onShowComparison}>
                Compare Pre/Post Checks
              </Button>
            </Box>
          )}
          {/* Show APRES logs button */}
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2, gap: 2, flexWrap: 'wrap' }}>
            <Button variant="outlined" onClick={onShowLogs}>Show Post-Checks Logs</Button>
          </Box>
        </>
      )}

    </Paper>
  );
};

export default ApresSection;