import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { HealthState } from '../types/common';
import { pipelineHealth } from '../api/xensql';
import { gatewayHealth } from '../api/queryvault';

const POLL_INTERVAL_MS = 30_000;

const defaultHealthState: HealthState = {
  xensql: { status: 'unreachable', dependencies: {} },
  queryvault: { status: 'unreachable', components: {} },
  lastChecked: new Date(),
};

const HealthContext = createContext<HealthState>(defaultHealthState);

export function HealthProvider({ children }: { children: React.ReactNode }) {
  const [health, setHealth] = useState<HealthState>(defaultHealthState);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const poll = useCallback(async () => {
    const [xensqlRes, qvRes] = await Promise.all([
      pipelineHealth(),
      gatewayHealth(),
    ]);

    setHealth({
      xensql: xensqlRes.data
        ? {
            status: xensqlRes.data.status === 'healthy' ? 'ok' : 'degraded',
            dependencies: xensqlRes.data.dependencies ?? {},
          }
        : { status: 'unreachable', dependencies: {} },
      queryvault: qvRes.data
        ? {
            status: qvRes.data.status === 'healthy' ? 'ok' : 'degraded',
            components: qvRes.data.components ?? {},
          }
        : { status: 'unreachable', components: {} },
      lastChecked: new Date(),
    });
  }, []);

  useEffect(() => {
    poll();
    timerRef.current = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [poll]);

  return React.createElement(HealthContext.Provider, { value: health }, children);
}

export function useHealth(): HealthState {
  return useContext(HealthContext);
}
