import { ApiResult } from '../types/common';

export async function apiCall<T>(url: string, options?: RequestInit): Promise<ApiResult<T>> {
  const start = performance.now();
  try {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...options?.headers },
      ...options,
    });
    const text = await res.text();
    const latencyMs = Math.round(performance.now() - start);
    let data: T | null = null;
    try { data = JSON.parse(text); } catch {}
    return { data, error: res.ok ? null : text, status: res.status, latencyMs, rawJson: text };
  } catch (err: any) {
    return { data: null, error: err.message || 'Network error', status: 0, latencyMs: Math.round(performance.now() - start), rawJson: '' };
  }
}
