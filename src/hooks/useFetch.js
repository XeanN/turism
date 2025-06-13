// src/hooks/useFetch.js
import { useState, useEffect } from 'react';

const useFetch = (url) => {
  const [data, setData] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const res = await fetch(url);
        const result = await res.json();

        if (!res.ok || result.success === false) {
          throw new Error(result.message || 'Error del servidor');
        }

        if (Array.isArray(result.data)) {
          setData(result.data);
        } else if (typeof result.data === 'object') {
          setData([result.data]); // importante para detalles
        } else {
          setData([]);
        }

        setError(null);
      } catch (err) {
        setError(err.message);
        setData([]);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [url]);

  return { data, loading, error };
};

export default useFetch;
