import React from 'react';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
// Box removed as Grid is not used here anymore for side-by-side of raw lines

const ComparisonModal = ({ open, onClose, comparisonResults }) => {
  if (!comparisonResults || Object.keys(comparisonResults).length === 0) {
    return (
        <Dialog open={open} onClose={onClose} maxWidth="sm">
            <DialogTitle>AVANT vs APRES Comparison</DialogTitle>
            <DialogContent>
                <Typography>No comparison data available or no differences found.</Typography>
            </DialogContent>
            <DialogActions>
                <Button onClick={onClose}>Close</Button>
            </DialogActions>
        </Dialog>
    );
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth scroll="paper"> {/* Changed to lg for better text fit */}
      <DialogTitle sx={{ borderBottom: 1, borderColor: 'divider' }}>AVANT vs APRES Comparison Details</DialogTitle>
      <DialogContent dividers sx={{backgroundColor: '#f9f9f9', p: {xs:1, sm:2 }}}>
        {Object.values(comparisonResults)
          .sort((a, b) => { 
              const statusOrder = { "Modifié": 1, "Nouveau": 2, "Supprimé": 3, "Identique": 4 };
              if (statusOrder[a.status] !== statusOrder[b.status]) {
                return statusOrder[a.status] - statusOrder[b.status];
              }
              return a.section_title.localeCompare(b.section_title);
          })
          .map((diff_section, index) => ( 
          <Accordion 
              key={diff_section.section_title + index} 
              defaultExpanded={diff_section.status !== "Identique"} 
              sx={{ mb: 1.5, '&:before': {display: 'none'}, border: 1, borderColor: 'divider', '&.Mui-expanded': { margin: '12px 0' } }}
              elevation={0}
              TransitionProps={{ unmountOnExit: true }}
          >
            <AccordionSummary 
                expandIcon={<ExpandMoreIcon />}
                sx={{ 
                    backgroundColor: diff_section.status === "Identique" ? 'rgba(0,0,0,0.02)' : 
                                     (diff_section.status === "Nouveau" ? 'success.light' : 
                                     (diff_section.status === "Supprimé" ? 'error.light' : 
                                     'action.hover' )), // Modifié uses default hover
                    borderBottom: '1px solid rgba(0,0,0,0.08)'
                }}
            >
              <Typography sx={{ fontWeight: 'medium', flexBasis: {xs: '60%', sm:'50%', md:'40%'}, flexShrink: 0 }}>
                {diff_section.section_title}
              </Typography>
              <Typography sx={{ 
                  color: diff_section.status === "Identique" ? 'text.secondary' : (diff_section.status === "Modifié" ? 'text.primary' : 'error.dark'), 
                  fontWeight: 'bold' 
                }}
              >
                Status: {diff_section.status}
              </Typography>
            </AccordionSummary>
            <AccordionDetails sx={{ backgroundColor: '#fff', borderTop: '1px solid rgba(0,0,0,0.08)', p: 1.5 }}>
                {/* Display the pre-formatted diff_text directly */}
                <Paper component="pre" variant="outlined" sx={{
                    p:1.5, 
                    whiteSpace: 'pre-wrap', 
                    wordBreak: 'break-all', 
                    maxHeight: '60vh', 
                    overflowY: 'auto', 
                    fontSize:'0.8rem', // Monospace for better alignment
                    fontFamily:'monospace', 
                    backgroundColor: '#fff', 
                    borderColor: 'rgba(0,0,0,0.1)' 
                }}>
                    {diff_section.diff_text || "(Error generating diff text or section identical)"}
                </Paper>
            </AccordionDetails>
          </Accordion>
        ))}
      </DialogContent>
      <DialogActions sx={{borderTop: 1, borderColor: 'divider', p:2}}>
        <Button onClick={onClose} variant="outlined">Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ComparisonModal;