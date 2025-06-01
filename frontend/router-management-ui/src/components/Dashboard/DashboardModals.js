import React from 'react';
import ComparisonModal from '../Common/ComparisonModal';
import LogModal from '../Common/LogModal';
import ConfirmationModal from '../Common/ConfirmationModal';
import UpdateModal from '../Update/UpdateModal';
import StreamingLogModal from '../Update/StreamingLogModal';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';

const DashboardModals = ({
  // Comparison Modal
  showComparisonDetailModal,
  closeComparisonDetailModal,
  comparisonResults,
  // Avant Logs Modal
  showAvantLogsModal,
  closeAvantLogsModal,
  avantLogs,
  // Apres Confirm Modal
  showApresConfirmModal,
  closeApresConfirmModal, // This is handleCancelApres
  confirmApres, // This is handleConfirmApres
  // Update Modal (filename input)
  isUpdateModalOpen,
  closeUpdateModal,
  startUpdateProcedure, // This is the main fn that takes filename
  // Streaming Log Modal (for update)
  isStreamingLogModalOpen,
  closeStreamingLogModal,
  streamingUpdateLogs,
  isUpdateInProgress,
  updateOperationResult,
  // File Viewer Modal
  fileViewerOpen,
  closeFileViewerModal,
  fileViewerContent,
  fileViewerFilename,
  // Apres Logs Modal
  showApresLogsModal,
  closeApresLogsModal,
  apresLogs,
}) => {
  return (
    <>
      <ComparisonModal
        open={showComparisonDetailModal}
        onClose={closeComparisonDetailModal}
        comparisonResults={comparisonResults}
      />
      <LogModal
        open={showAvantLogsModal}
        onClose={closeAvantLogsModal}
        logs={avantLogs}
        title="Pre-Checks Execution Logs"
      />
      <LogModal
        open={showApresLogsModal}
        onClose={closeApresLogsModal}
        logs={apresLogs}
        title="Post-Checks Execution Logs"
      />
      <ConfirmationModal
        open={showApresConfirmModal}
        onClose={closeApresConfirmModal}
        title="Run Post-Checks"
        message="Are you ready to run the post-checks? This will compare the current state against the initial pre-checks."
        confirmText="Run Post-Checks"
        cancelText="Cancel"
        onConfirm={confirmApres}
      />
      <UpdateModal
        open={isUpdateModalOpen}
        onClose={closeUpdateModal}
        onConfirm={startUpdateProcedure} // UpdateModal's onConfirm will pass the filename
      />
      <StreamingLogModal
        open={isStreamingLogModalOpen}
        onClose={closeStreamingLogModal}
        logs={streamingUpdateLogs}
        title="Software Update Progress"
        isLoading={isUpdateInProgress}
        finalStatus={updateOperationResult}
      />
      <Dialog open={fileViewerOpen} onClose={closeFileViewerModal} maxWidth="lg" fullWidth scroll="paper">
        <DialogTitle>Viewing: {fileViewerFilename}</DialogTitle>
        <DialogContent dividers>
          <Paper elevation={0} sx={{ p: 2, maxHeight: '75vh', overflow: 'auto', backgroundColor: '#f5f5f5' }}>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: '0.875rem' }}>
              {fileViewerContent || "No content or file is empty."}
            </pre>
          </Paper>
        </DialogContent>
        <DialogActions><Button onClick={closeFileViewerModal}>Close</Button></DialogActions>
      </Dialog>
    </>
  );
};

export default DashboardModals;