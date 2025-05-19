import axios from 'axios';

const API_BASE_URL = 'http://localhost:5001/api'; // Your Flask API URL

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
export const runUpdateProcedure = (updateData) => {
  // updateData should contain { ident_data, password, image_file }
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
  // This will return the raw content, browser might try to download
  // For display, you might fetch and then show in a <pre> tag or dedicated viewer
  return apiClient.get(`/files/${filename}`, { responseType: 'text' });
};

export const deleteGeneratedFile = (filename) => {
  return apiClient.delete(`/files/${filename}`);
};

export default apiClient;