import axios from 'axios';

export const API_BASE_URL = 'http://localhost:5000/api'; // Your Flask API URL

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// --- Auth & Connection ---
export const testConnection = (credentials) => {
  return apiClient.post('/login', credentials);
};

// --- AVANT ---
// Only synchronous (full result after completion)
export const runAvantChecks = (credentials) => {
  return apiClient.post('/run_avant', credentials);
}

// --- UPDATE ---
// This function signature is kept for consistency, but the actual streaming
// will be handled by `fetch` directly in DashboardPage.js to manage SSE.
// This function can still be used if a non-streaming initiation is ever needed
// or if it's refactored to return a promise that wraps the fetch stream.
export const runUpdateProcedure = (updateData, credentials, identData) => {
  // Always build the payload with { ip, username, password, image_file }
  const payload = {
    ip: credentials.ip || identData?.ip || updateData?.ip,
    username: credentials?.username || identData?.username || updateData?.username,
    password: credentials?.password || updateData?.password,
    image_file: updateData?.image_file,
  };
  // Ensure the payload is correct before sending
  return apiClient.post('/run_update', payload);
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