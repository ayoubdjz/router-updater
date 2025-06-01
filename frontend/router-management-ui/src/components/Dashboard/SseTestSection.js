import React from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import StreamingLogBox from '../Common/StreamingLogBox';

const SseTestSection = ({
  showSseTest = true, // Always visible for dev
  sseTestLogs,
  sseTestFullLogs,
  showSseTestFullLogs,
  setShowSseTestFullLogs,
  handleStartSseTest,
  handleCloseSseTest,
}) => {
  return (
    <Box sx={{ my: 3, p:2, border: '1px dashed grey' }}>
       <Typography variant="h6" gutterBottom>SSE Test Area (Dev)</Typography>
      <Button variant="outlined" color="info" onClick={handleStartSseTest} sx={{ mr: 2 }}>
        Test SSE (Show Time Stream)
      </Button>
      {showSseTest && (
        <Box sx={{ maxWidth: 600, mt: 2 }}>
          <StreamingLogBox
            logs={sseTestLogs}
            title="SSE Test: Time Stream (onmessage)"
            isLoading={sseTestLogs.length > 0 && sseTestLogs.length < 6 && !sseTestLogs.find(l => l.includes('closed'))} // Example loading condition
            actions={
              <>
                <Button onClick={handleCloseSseTest} size="small">Close Stream</Button>
                {sseTestFullLogs.length > 0 && (
                  <Button onClick={() => setShowSseTestFullLogs((v) => !v)} sx={{ ml: 1 }} size="small">
                    {showSseTestFullLogs ? 'Hide "logs" Event Data' : 'Show "logs" Event Data'}
                  </Button>
                )}
              </>
            }
          />
          {showSseTestFullLogs && sseTestFullLogs.length > 0 && (
            <Box sx={{ mt: 2 }}>
              <StreamingLogBox
                logs={sseTestFullLogs}
                title="SSE Test: Complete Logs (event: logs)"
                isLoading={false} // Assuming 'logs' event sends all data at once
              />
            </Box>
          )}
        </Box>
      )}
    </Box>
  );
};

export default SseTestSection;