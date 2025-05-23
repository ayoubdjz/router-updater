import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import { BrowserRouter } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { AuthProvider } from './contexts/AuthContext';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'; // Correct import
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'; // Correct import

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, 
      gcTime: 1000 * 60 * 10,  
      retry: 1, 
      refetchOnWindowFocus: false, 
    },
    mutations: {
      retry: 0, 
    },
  },
});

const theme = createTheme({ /* ... your theme ... */ });

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={theme}>
        <AuthProvider>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
);