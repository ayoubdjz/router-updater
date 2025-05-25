import axios from 'axios';

export const API_BASE_URL = 'http://localhost:5001/api'; // Your Flask API URL

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// --- Auth & Connection ---
export const testConnection = (credentials) => {
  return apiClient.post('/test_connection', credentials);
};

// --- AVANT ---
export const runAvantChecks = (credentials) => {
  return apiClient.post('/run_avant', credentials);
};

// --- UPDATE ---
// This function signature is kept for consistency, but the actual streaming
// will be handled by `fetch` directly in DashboardPage.js to manage SSE.
// This function can still be used if a non-streaming initiation is ever needed
// or if it's refactored to return a promise that wraps the fetch stream.
export const runUpdateProcedure = (updateData) => {
  // updateData should contain { ident_data, password, image_file }
  // For actual streaming, DashboardPage.js uses fetch directly.
  // This POST could be used to *initiate* a task that then streams,
  // but the current implementation streams directly from this POST.
  return apiClient.post('/run_update', updateData);
};

// --- APRES ---
export const runApresChecks = (apresData) => {
  // apresData should contain { ident_data, password }
  return apiClient.post('/run_apres', apresData);
};

// --- LOCK ---
export const unlockRouter = (lockFilePath) => {
  return apiClient.post('/unlock_router', { lock_file_path: lockFilePath });
};

// --- FILES ---
export const listGeneratedFiles = () => {
  return apiClient.get('/files');
};

export const getFileContent = (filename) => {
  return apiClient.get(`/files/${filename}`, { responseType: 'text' });
};

export const deleteGeneratedFile = (filename) => {
  return apiClient.delete(`/files/${filename}`);
};

export default apiClient;