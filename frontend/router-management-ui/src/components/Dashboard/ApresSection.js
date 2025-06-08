import React from 'react';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import CircularProgress from '@mui/material/CircularProgress';
import Alert from '@mui/material/Alert';
import StructuredDataDisplay from '../Common/StructuredDataDisplay';
import ApresRunner from '../Apres/ApresRunner'; // Existing component
import { useAuth } from '../../contexts/AuthContext'; // To get sessionData
import ComparisonModal from '../Common/ComparisonModal'; // Import the new modal component

const ApresSection = ({
  apresCriticalError, // The error message string
  handleTriggerApres,
  handleReloadApres, // Also used for retry
  handleApresProcessFinished,
  setShowComparisonDetailModal,
  setShowApresLogsModal, // <-- add this prop
  // isActionLoading, // If general action loading affects Apres buttons
}) => {
  const { sessionData } = useAuth();
  const showApresRunner = sessionData.viewState === 'apres_running' && !sessionData.apresCompleted && !apresCriticalError;
  const showApresResultsDisplay = sessionData.apresCompleted && sessionData.apresData && !apresCriticalError;
  // Use comparisonResults from sessionData (string)
  const hasComparisonResults = sessionData.comparisonResults && typeof sessionData.comparisonResults === 'string' && sessionData.comparisonResults.trim().length > 0;
  const [showComparisonModal, setShowComparisonModal] = React.useState(false);

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
        {(!showApresRunner && !sessionData.apresCompleted) && (
          <Button 
            variant="contained" 
            color="secondary" 
            onClick={handleTriggerApres} 
            disabled={sessionData.updateInProgress}
          >
            Run Post-Checks
          </Button>
        )}
        {sessionData.apresCompleted && (
          <Button 
            variant="outlined" 
            color="secondary" 
            onClick={handleReloadApres} 
            disabled={showApresRunner || sessionData.updateInProgress}
          >
          {showApresRunner ? <CircularProgress size={20} sx={{mr:1}}/> : null} Reload Post-Checks
          </Button>
        )}
      </Box>

      {/* Structured Data Display for APRES */}
      {sessionData.apresCompleted && (
        <>
          <StructuredDataDisplay data={sessionData.apresData} titlePrefix="APRES" />
          {/* Show comparison button if comparisonResults string exists */}
          {hasComparisonResults && (
            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
              <Button variant="outlined" onClick={() => setShowComparisonModal(true)}>
                Compare Pre/Post Checks
              </Button>
            </Box>
          )}
          {/* Show APRES logs button */}
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2, gap: 2, flexWrap: 'wrap' }}>
            <Button variant="outlined" onClick={() => setShowApresLogsModal(true)}>Show Post-Checks Logs</Button>
          </Box>
          {/* Comparison Modal for string result */}
          {hasComparisonResults && (
            <ComparisonModal
              open={showComparisonModal}
              onClose={() => setShowComparisonModal(false)}
              comparisonResults={sessionData.comparisonResults}
            />
          )}
        </>
      )}

      {/* APRES runner (loading state) */}
      {showApresRunner && <ApresRunner onApresProcessFinished={handleApresProcessFinished} />}

      {sessionData.viewState === 'apres_completed_with_issues' && !apresCriticalError && (
        <Alert severity="warning" sx={{mt:2}}>Post-checks completed with some discrepancies. Review logs and comparison.</Alert>
      )}
    </Paper>
  );
};

export default ApresSection;