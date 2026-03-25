import { useState, useCallback } from 'react';
import { ApiResult } from '../types/common';

export function useApiCall<T>() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ApiResult<T> | null>(null);

  const execute = useCallback(async (apiFn: () => Promise<ApiResult<T>>) => {
    setLoading(true);
    try {
      const res = await apiFn();
      setResult(res);
    } finally {
      setLoading(false);
    }
  }, []);

  const clear = useCallback(() => setResult(null), []);
  return { loading, result, execute, clear };
}
