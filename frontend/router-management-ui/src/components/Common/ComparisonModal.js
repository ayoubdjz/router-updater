import React from 'react';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';

// Expects: comparisonResults = { section_key: { avant_content: [...], apres_content: [...] } }
// If you want to pass in two objects (avantData, apresData), adjust accordingly.
const ComparisonModal = ({ open, onClose, comparisonResults }) => {
  // If the backend now just returns two objects: avantData, apresData
  // You can adjust this logic to accept those directly.
  if (!comparisonResults || Object.keys(comparisonResults).length === 0) {
    return (
      <Dialog open={open} onClose={onClose} maxWidth="sm">
        <DialogTitle>AVANT vs APRES Comparison</DialogTitle>
        <DialogContent>
          <Typography>No comparison data available.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Close</Button>
        </DialogActions>
      </Dialog>
    );
  }

  // Helper to merge and display content for special sections
  const getSectionContent = (sectionKey, sectionData) => {
    // Interfaces: merge up and down
    if (sectionKey === 'Informations sur les interfaces :') {
      const up = sectionData['interfaces_up'] || [];
      const down = sectionData['interfaces_down'] || [];
      const upLabel = up.length ? 'Interfaces UP:\n' + up.join('\n') : '';
      const downLabel = down.length ? '\nInterfaces DOWN:\n' + down.join('\n') : '';
      const content = (upLabel + downLabel).trim();
      return content || 'Aucune interface trouvée.';
    }
    // Routes: use route summary
    if (sectionKey === 'Informations sur les routes :') {
      const summary = sectionData['route_summary'];
      return summary && summary.length ? summary.join('\n') : 'Aucune information de routes.';
    }
    // Logs: merge chassisd and messages
    if (sectionKey === "Logs des erreurs critiques :") {
      const chassisd = sectionData['critical_logs_chassisd'] || [];
      const messages = sectionData['critical_logs_messages'] || [];
      let content = '';
      if (chassisd.length) content += "Logs des erreurs critiques dans 'chassisd':\n" + chassisd.join('\n') + '\n';
      if (messages.length) content += "Logs des erreurs critiques dans 'messages':\n" + messages.join('\n');
      return content.trim() || 'Aucune erreur critique trouvée.';
    }
    // Default: show joined content or empty message
    if (Array.isArray(sectionData)) {
      return sectionData.length ? sectionData.join('\n') : 'Aucune donnée.';
    }
    if (typeof sectionData === 'string') {
      return sectionData.trim() ? sectionData : 'Aucune donnée.';
    }
    return 'Aucune donnée.';
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth scroll="paper">
      <DialogTitle sx={{ borderBottom: 1, borderColor: 'divider' }}>AVANT vs APRES Visual Comparison</DialogTitle>
      <DialogContent dividers sx={{ backgroundColor: '#f9f9f9', p: { xs: 1, sm: 2 } }}>
        {Object.entries(comparisonResults).map(([sectionKey, sectionData], idx) => {
          // Remove duplicate/empty sections for interfaces and logs
          const skipSections = [
            'Logs des erreurs critiques :',
            'Informations sur les interfaces :'
          ];
          if (skipSections.includes(sectionKey)) {
            const contentAvant = getSectionContent(sectionKey, sectionData.avant_content);
            const contentApres = getSectionContent(sectionKey, sectionData.apres_content);
            if (
              (!contentAvant || contentAvant === 'Aucune donnée.' || contentAvant === 'Aucune interface trouvée.' || contentAvant === 'Aucune erreur critique trouvée.') &&
              (!contentApres || contentApres === 'Aucune donnée.' || contentApres === 'Aucune interface trouvée.' || contentApres === 'Aucune erreur critique trouvée.')
            ) {
              return null;
            }
          }
          return (
            <Paper key={sectionKey + idx} sx={{ mb: 3, p: 2, border: 1, borderColor: 'divider' }}>
              <Typography variant="h6" sx={{ mb: 2 }}>{sectionKey}</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>AVANT</Typography>
                  <Paper component="pre" variant="outlined" sx={{ p: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', minHeight: 120, backgroundColor: '#fff', fontFamily: 'monospace', fontSize: '0.9rem', overflowX: 'auto' }}>
                    {getSectionContent(sectionKey, sectionData.avant_content)}
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>APRES</Typography>
                  <Paper component="pre" variant="outlined" sx={{ p: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', minHeight: 120, backgroundColor: '#fff', fontFamily: 'monospace', fontSize: '0.9rem', overflowX: 'auto' }}>
                    {getSectionContent(sectionKey, sectionData.apres_content)}
                  </Paper>
                </Grid>
              </Grid>
            </Paper>
          );
        })}
      </DialogContent>
      <DialogActions sx={{ borderTop: 1, borderColor: 'divider', p: 2 }}>
        <Button onClick={onClose} variant="outlined">Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ComparisonModal;