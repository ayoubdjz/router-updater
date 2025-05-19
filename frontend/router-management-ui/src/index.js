import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css'; // You can keep this or remove if MUI handles all styling
import App from './App';
import { BrowserRouter } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles'; // For MUI
import { AuthProvider } from './contexts/AuthContext'; // Add this


// Optional: Define a basic theme for MUI
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2', // Example primary color
    },
    secondary: {
      main: '#dc004e', // Example secondary color
    },
  },
});


const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <AuthProvider> {/* Add this */}
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AuthProvider> {/* And this */}
    </ThemeProvider>
  </React.StrictMode>
);