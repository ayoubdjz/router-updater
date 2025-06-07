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

// --- UPDATE (SSE streaming) ---
export const runUpdateProcedureStream = (updateData, credentials, identData, onLog, onResult, onError, signal) => {
  // Build the payload
  const payload = {
    ip: credentials.ip || identData?.ip || updateData?.ip,
    username: credentials?.username || identData?.username || updateData?.username,
    password: credentials?.password || updateData?.password,
    image_file: updateData?.image_file,
  };
  // Use EventSource for SSE (but EventSource does not support POST, so use fetch with ReadableStream)
  // We'll use fetch and parse the SSE stream manually
  const url = `${API_BASE_URL}/run_update`;
  const fetchOptions = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal,
  };
  // Return a promise that resolves when the stream ends
  return fetch(url, fetchOptions).then(async (response) => {
    if (!response.body) throw new Error('No response body for SSE');
    const reader = response.body.getReader();
    let buffer = '';
    let decoder = new TextDecoder('utf-8');
    let isDone = false;
    while (!isDone) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let lines = buffer.split(/\r?\n/);
      buffer = lines.pop(); // last line may be incomplete
      let expectingResult = false;
      for (let line of lines) {
        if (line.startsWith('event: result')) {
          expectingResult = true;
        } else if (line.startsWith('data: ')) {
          const dataStr = line.replace('data: ', '');
          if (expectingResult) {
            // This is the final JSON result, do not display its logs array
            try {
              console.log('[SSE DEBUG] Received final JSON result:', dataStr);
              const result = JSON.parse(dataStr);
              if (onResult) onResult(result);
            } catch (e) {
              console.error('[SSE DEBUG] Error parsing final JSON result:', e, dataStr);
              if (onError) onError(e);
            }
            expectingResult = false;
          } else {
            // This is a streamed log line, display it
            if (onLog) onLog(dataStr);
          }
        }
      }
    }
  }).catch((err) => {
    if (onError) onError(err);
  });
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