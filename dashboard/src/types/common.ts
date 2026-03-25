export interface ApiResult<T> {
  data: T | null;
  error: string | null;
  status: number;
  latencyMs: number;
  rawJson: string;
}

export interface HealthState {
  xensql: { status: 'ok' | 'degraded' | 'unreachable'; dependencies: Record<string, boolean> };
  queryvault: { status: 'ok' | 'degraded' | 'unreachable'; components: Record<string, string> };
  lastChecked: Date;
}
