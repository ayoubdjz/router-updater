import { useState, useCallback, useRef, useEffect } from 'react';
import { API_BASE_URL } from '../api/routerApi'; // Assuming API_BASE_URL is exported here

export const useSseTest = () => {
  const [showSseTest, setShowSseTest] = useState(true);
  const [sseTestLogs, setSseTestLogs] = useState([]);
  const [sseTestFullLogs, setSseTestFullLogs] = useState([]); // For the 'logs' event type
  const [showSseTestFullLogs, setShowSseTestFullLogs] = useState(false);
  const sseTestRef = useRef(null);

  const handleStartSseTest = useCallback(() => {
    setShowSseTest(true);
    setSseTestLogs([]);
    setSseTestFullLogs([]);
    setShowSseTestFullLogs(false);

    if (sseTestRef.current) {
      sseTestRef.current.close();
    }

    const es = new window.EventSource(`${API_BASE_URL}/test_sse`);
    sseTestRef.current = es;

    es.onmessage = (event) => { // Default event
      setSseTestLogs((prev) => [...prev, event.data]);
    };

    es.addEventListener('logs', (event) => { // Custom 'logs' event
      try {
        const logsArr = JSON.parse(event.data);
        setSseTestFullLogs(logsArr);
      } catch (e) {
        setSseTestFullLogs([`[Error parsing logs event]: ${e.message}`]);
      }
    });

    es.onerror = () => {
      setSseTestLogs((prev) => [...prev, '[SSE connection closed or error]']);
      es.close();
      sseTestRef.current = null;
    };
  }, []);

  const handleCloseSseTest = useCallback(() => {
    setShowSseTest(false);
    if (sseTestRef.current) {
      sseTestRef.current.close();
      sseTestRef.current = null;
    }
  }, []);
  
  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (sseTestRef.current) {
        sseTestRef.current.close();
      }
    };
  }, []);

  return {
    showSseTest,
    sseTestLogs,
    sseTestFullLogs,
    showSseTestFullLogs,
    setShowSseTestFullLogs, // To toggle visibility from the component
    handleStartSseTest,
    handleCloseSseTest,
  };
};