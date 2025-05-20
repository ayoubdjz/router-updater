import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Chip from '@mui/material/Chip';

const TabPanel = (props) => {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`data-tabpanel-${index}`}
      aria-labelledby={`data-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: {xs: 1, sm: 2}, border: 1, borderColor: 'divider', borderTop: 0, maxHeight: '60vh', overflowY: 'auto' }}>
            {children}
        </Box>
      )}
    </div>
  );
};

const renderDataContent = (data, sectionKey) => {
  if (data === null || data === undefined) {
    return <Typography variant="body2" sx={{fontStyle: 'italic', p:1}}>No data available for this section.</Typography>;
  }
  if (typeof data === 'string' && data.trim() === '') {
     // Handle specific messages for "not configured" or "none found"
     if (data.toLowerCase().includes("n'est pas configuré") || data.toLowerCase().includes("aucun") || data.toLowerCase().includes("not configured") || data.toLowerCase().includes("not running")) {
        return <Chip label={data.trim()} color="info" variant="outlined" size="small" sx={{m:1}} />;
     }
    return <Typography variant="body2" sx={{fontStyle: 'italic', p:1}}>No data available for this section.</Typography>;
  }


  if (typeof data === 'string') {
    if (data.toLowerCase().includes("n'est pas configuré") || data.toLowerCase().includes("aucun") || data.toLowerCase().includes("not configured") || data.toLowerCase().includes("not running")) {
        return <Chip label={data.trim()} color="info" variant="outlined" size="small" sx={{m:1}} />;
    }
    if (data.includes('\n') || data.length > 150) { // Heuristic for preformatted text
      return <Paper component="pre" variant="outlined" sx={{ p: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '0.8rem', fontFamily: 'monospace', backgroundColor:'#f9f9f9' }}>{data}</Paper>;
    }
    return <Typography variant="body2" sx={{p:1}}>{data}</Typography>;
  } else if (Array.isArray(data)) {
    if (data.length === 0) {
      return <Chip label="No items in list" color="info" variant="outlined" size="small" sx={{m:1}} />;
    }
    if (typeof data[0] === 'string') {
      return (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, p:1 }}>
            {data.map((item, index) => <Chip key={`${sectionKey}-${index}`} label={item} size="small" variant="outlined" />)}
        </Box>
      );
    }
    if (typeof data[0] === 'object' && data[0] !== null) {
      const headers = Object.keys(data[0]);
      return (
        <TableContainer component={Paper} elevation={0} variant="outlined">
          <Table size="small" aria-label={`${sectionKey} table`} stickyHeader>
            <TableHead sx={{ backgroundColor: 'action.hover' }}>
              <TableRow>
                {headers.map(header => <TableCell key={header} sx={{fontWeight: 'bold', textTransform: 'capitalize'}}>{header.replace(/_/g, ' ')}</TableCell>)}
              </TableRow>
            </TableHead>
            <TableBody>
              {data.map((row, rowIndex) => (
                <TableRow key={rowIndex} hover sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                  {headers.map(header => <TableCell key={`${rowIndex}-${header}`}>{String(row[header])}</TableCell>)}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      );
    }
  } else if (typeof data === 'object' && data !== null) { 
    return (
      <Box sx={{p:1}}>
        {Object.entries(data).map(([key, value]) => (
          key !== 'section_title' && ( // Avoid printing section_title if it's part of the object itself
            <Typography key={key} variant="body2" sx={{ mb: 0.5 }}>
              <strong style={{textTransform: 'capitalize'}}>{key.replace(/_/g, ' ')}:</strong> {String(value)}
            </Typography>
          )
        ))}
      </Box>
    );
  }
  return <Typography variant="body2" sx={{p:1}}><i>Unsupported data format for display.</i></Typography>;
};

const StructuredDataDisplay = ({ data, titlePrefix = "" }) => {
  const [currentTab, setCurrentTab] = useState(0);

  if (!data || Object.keys(data).length === 0) {
    return <Typography sx={{mt: 2, fontStyle: 'italic'}}>No structured data to display.</Typography>;
  }

  const handleChangeTab = (event, newValue) => {
    setCurrentTab(newValue);
  };

  const predefinedOrder = [
    'basic_info', 'routing_engine', 'interfaces_up', 'interfaces_down', 'arp_table', 
    'route_summary', 'ospf_info', 'isis_info', 'mpls_info', 'ldp_info', 'rsvp_info', 
    'lldp_info', 'lsp_info', 'bgp_summary', 'system_services', 'configured_protocols', 
    'firewall_config', 'critical_logs_messages', 'critical_logs_chassisd', 'full_config_set'
  ];

  const displayableEntries = predefinedOrder
    .filter(key => data[key] !== undefined) // Keep only keys present in data
    .map(key => ({
      key,
      value: data[key],
      // Attempt to get a human-readable title
      title: data[key]?.section_title || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }))
    .filter(({value}) => { // Filter out sections that are completely empty or null after mapping
        if (value === null || value === undefined) return false;
        if (typeof value === 'string' && value.trim() === '') return false;
        if (Array.isArray(value) && value.length === 0) return false;
        if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0 && value.constructor === Object) return false;
        return true;
    });
    
  // Add any keys from data that were not in predefinedOrder (e.g. custom keys from API)
  Object.entries(data).forEach(([key, value]) => {
    if (!predefinedOrder.includes(key)) {
      const isAlreadyAdded = displayableEntries.some(entry => entry.key === key);
      if (!isAlreadyAdded) {
         // Filter this extra entry too
        let shouldAdd = true;
        if (value === null || value === undefined) shouldAdd = false;
        if (typeof value === 'string' && value.trim() === '') shouldAdd = false;
        if (Array.isArray(value) && value.length === 0) shouldAdd = false;
        if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0 && value.constructor === Object) shouldAdd = false;
        if (shouldAdd) {
            displayableEntries.push({
                key,
                value,
                title: value?.section_title || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
            });
        }
      }
    }
  });
  
  if (displayableEntries.length === 0) {
    return <Typography sx={{mt: 2, fontStyle: 'italic'}}>No relevant structured data to display.</Typography>;
  }

  return (
    <Box sx={{ my: 2, width: '100%' }}>
      <Typography variant="h6" gutterBottom>{titlePrefix} Information Summary</Typography>
      <Paper elevation={1} variant="outlined">
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={handleChangeTab}
            variant="scrollable"
            scrollButtons="auto"
            aria-label={`${titlePrefix} structured data tabs`}
          >
            {displayableEntries.map(({key, title}, index) => (
              <Tab 
                label={title} 
                id={`${titlePrefix}-data-tab-${index}`} 
                aria-controls={`${titlePrefix}-data-tabpanel-${index}`}
                key={key}
                sx={{textTransform: 'none', fontSize: '0.875rem'}}
              />
            ))}
          </Tabs>
        </Box>
        {displayableEntries.map(({key, value}, index) => (
          <TabPanel value={currentTab} index={index} key={`${key}-panel`}>
            {renderDataContent(value, key)}
          </TabPanel>
        ))}
      </Paper>
    </Box>
  );
};

export default StructuredDataDisplay;