import React from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';

const DataSection = ({ title, data, defaultExpanded = false }) => {
  if (data === null || data === undefined || (typeof data === 'string' && data.trim() === '')) {
    return null;
  }

  let content;
  if (typeof data === 'string') {
    content = <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: '0.875rem' }}>{data}</pre>;
  } else if (Array.isArray(data)) {
    if (data.length === 0) {
      content = <Typography variant="body2"><i>No data available.</i></Typography>;
    } else if (typeof data[0] === 'string') {
      content = (
        <ul style={{ paddingLeft: '20px', margin: 0 }}>
          {data.map((item, index) => <li key={index}><Typography variant="body2">{item}</Typography></li>)}
        </ul>
      );
    } else if (typeof data[0] === 'object' && data[0] !== null) { // Assuming list of objects for a table
      const headers = Object.keys(data[0]);
      content = (
        <TableContainer component={Paper} elevation={0} variant="outlined">
          <Table size="small" aria-label={`${title} table`}>
            <TableHead sx={{ backgroundColor: '#f0f0f0'}}>
              <TableRow>
                {headers.map(header => <TableCell key={header} sx={{fontWeight: 'bold'}}>{header.replace(/_/g, ' ').toUpperCase()}</TableCell>)}
              </TableRow>
            </TableHead>
            <TableBody>
              {data.map((row, rowIndex) => (
                <TableRow key={rowIndex}>
                  {headers.map(header => <TableCell key={`${rowIndex}-${header}`}>{String(row[header])}</TableCell>)}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      );
    } else {
      content = <Typography variant="body2"><i>Unsupported array data format.</i></Typography>;
    }
  } else if (typeof data === 'object' && data !== null) { // Simple key-value object
    content = (
      <Box>
        {Object.entries(data).map(([key, value]) => (
          key !== 'section_title' && ( // Avoid printing section_title if it's part of the object
            <Typography key={key} variant="body2" gutterBottom>
              <strong style={{textTransform: 'capitalize'}}>{key.replace(/_/g, ' ')}:</strong> {String(value)}
            </Typography>
          )
        ))}
      </Box>
    );
  } else {
    content = <Typography variant="body2"><i>Invalid data format.</i></Typography>;
  }

  return (
    <Accordion defaultExpanded={defaultExpanded} sx={{mb: 1}}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls={`${title}-content`} id={`${title}-header`}>
        <Typography variant="subtitle1" sx={{fontWeight: 'medium'}}>{title}</Typography>
      </AccordionSummary>
      <AccordionDetails sx={{ backgroundColor: '#fafafa', maxHeight: '400px', overflowY: 'auto' }}>
        {content}
      </AccordionDetails>
    </Accordion>
  );
};


const StructuredDataDisplay = ({ data }) => {
  if (!data || Object.keys(data).length === 0) {
    return <Typography sx={{mt: 2}}>No structured data to display.</Typography>;
  }

  // Predefined order or specific handling for sections
  const order = [
    'basic_info', 'routing_engine', 'interfaces_up', 'interfaces_down', 'arp_table', 
    'route_summary', 'ospf_info', 'isis_info', 'mpls_info', 'ldp_info', 'rsvp_info', 
    'lldp_info', 'lsp_info', 'bgp_summary', 'system_services', 'configured_protocols', 
    'firewall_config', 'critical_logs_messages', 'critical_logs_chassisd', 'full_config_set'
  ];
  
  const knownSections = new Set(order);

  return (
    <Box sx={{ my: 2 }}>
      <Typography variant="h6" gutterBottom>Detailed Information</Typography>
      {order.map(key => {
        if (data[key] !== undefined) {
          const title = data[key]?.section_title || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          return <DataSection key={key} title={title} data={data[key]} defaultExpanded={key === 'basic_info'} />;
        }
        return null;
      })}
      {/* Display any other sections not in the predefined order */}
      {Object.entries(data).map(([key, value]) => {
        if (!knownSections.has(key)) {
          const title = value?.section_title || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          return <DataSection key={key} title={title} data={value} />;
        }
        return null;
      })}
    </Box>
  );
};

export default StructuredDataDisplay;