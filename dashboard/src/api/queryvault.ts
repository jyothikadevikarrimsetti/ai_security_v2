import { apiCall } from './client';
import { QV_BASE } from '../config/endpoints';
import { ApiResult } from '../types/common';
import {
  GatewayQueryRequest,
  GatewayQueryResponse,
  GatewayHealthResponse,
  ComplianceReportResponse,
  StandardsResponse,
  DashboardResponse,
  ThreatAnalysisResponse,
  PatternsResponse,
  AlertsResponse,
  AlertActionResponse,
} from '../types/queryvault';
import { MockUsersResponse, MockTokenResponse } from '../types/mockUsers';
import {
  PolicyRolesResponse,
  PolicyTablesResponse,
  PolicyColumnsResponse,
  RolePolicyUpdate,
} from '../types/policies';

export function gatewayQuery(req: GatewayQueryRequest): Promise<ApiResult<GatewayQueryResponse>> {
  return apiCall<GatewayQueryResponse>(`${QV_BASE}/gateway/query`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export function gatewayHealth(): Promise<ApiResult<GatewayHealthResponse>> {
  return apiCall<GatewayHealthResponse>(`${QV_BASE}/gateway/health`);
}

export function complianceReport(standard?: string, timeRangeDays?: number): Promise<ApiResult<ComplianceReportResponse>> {
  const params = new URLSearchParams();
  if (standard) params.set('standard', standard);
  if (timeRangeDays !== undefined) params.set('time_range_days', String(timeRangeDays));
  const qs = params.toString();
  return apiCall<ComplianceReportResponse>(`${QV_BASE}/compliance/report${qs ? `?${qs}` : ''}`);
}

export function complianceStandards(): Promise<ApiResult<StandardsResponse>> {
  return apiCall<StandardsResponse>(`${QV_BASE}/compliance/standards`);
}

export function complianceDashboard(timeRangeDays?: number): Promise<ApiResult<DashboardResponse>> {
  const qs = timeRangeDays !== undefined ? `?time_range_days=${timeRangeDays}` : '';
  return apiCall<DashboardResponse>(`${QV_BASE}/compliance/dashboard${qs}`);
}

export function threatAnalysis(timeRangeDays?: number, userId?: string): Promise<ApiResult<ThreatAnalysisResponse>> {
  const params = new URLSearchParams();
  if (timeRangeDays !== undefined) params.set('time_range_days', String(timeRangeDays));
  if (userId) params.set('user_id', userId);
  const qs = params.toString();
  return apiCall<ThreatAnalysisResponse>(`${QV_BASE}/threat/analysis${qs ? `?${qs}` : ''}`);
}

export function threatPatterns(): Promise<ApiResult<PatternsResponse>> {
  return apiCall<PatternsResponse>(`${QV_BASE}/threat/patterns`);
}

export function listAlerts(params: {
  severity?: string;
  status?: string;
  user_id?: string;
  time_range_days?: number;
  limit?: number;
  offset?: number;
}): Promise<ApiResult<AlertsResponse>> {
  const searchParams = new URLSearchParams();
  if (params.severity) searchParams.set('severity', params.severity);
  if (params.status) searchParams.set('status', params.status);
  if (params.user_id) searchParams.set('user_id', params.user_id);
  if (params.time_range_days !== undefined) searchParams.set('time_range_days', String(params.time_range_days));
  if (params.limit !== undefined) searchParams.set('limit', String(params.limit));
  if (params.offset !== undefined) searchParams.set('offset', String(params.offset));
  const qs = searchParams.toString();
  return apiCall<AlertsResponse>(`${QV_BASE}/alerts${qs ? `?${qs}` : ''}`);
}

export function acknowledgeAlert(alertId: string): Promise<ApiResult<AlertActionResponse>> {
  return apiCall<AlertActionResponse>(`${QV_BASE}/alerts/${encodeURIComponent(alertId)}/acknowledge`, {
    method: 'POST',
  });
}

export function resolveAlert(alertId: string): Promise<ApiResult<AlertActionResponse>> {
  return apiCall<AlertActionResponse>(`${QV_BASE}/alerts/${encodeURIComponent(alertId)}/resolve`, {
    method: 'POST',
  });
}

export function listMockUsers(): Promise<ApiResult<MockUsersResponse>> {
  return apiCall<MockUsersResponse>(`${QV_BASE}/mock-users`);
}

export function generateMockToken(oid: string): Promise<ApiResult<MockTokenResponse>> {
  return apiCall<MockTokenResponse>(`${QV_BASE}/mock-users/${encodeURIComponent(oid)}/token`, {
    method: 'POST',
  });
}

// ── Policy Management ────────────────────────────────────────

export function listPolicyRoles(): Promise<ApiResult<PolicyRolesResponse>> {
  return apiCall<PolicyRolesResponse>(`${QV_BASE}/policies/roles`);
}

export function getPolicyRoleDetail(roleName: string): Promise<ApiResult<PolicyRolesResponse>> {
  return apiCall<PolicyRolesResponse>(`${QV_BASE}/policies/roles/${encodeURIComponent(roleName)}`);
}

export function updatePolicyRole(roleName: string, payload: RolePolicyUpdate): Promise<ApiResult<{ status: string }>> {
  return apiCall<{ status: string }>(`${QV_BASE}/policies/roles/${encodeURIComponent(roleName)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export function listPolicyTables(): Promise<ApiResult<PolicyTablesResponse>> {
  return apiCall<PolicyTablesResponse>(`${QV_BASE}/policies/tables`);
}

export function updatePolicyTable(tableName: string, sensitivity: number, domain: string): Promise<ApiResult<{ status: string }>> {
  return apiCall<{ status: string }>(`${QV_BASE}/policies/tables/${encodeURIComponent(tableName)}`, {
    method: 'PUT',
    body: JSON.stringify({ sensitivity_level: sensitivity, domain }),
  });
}

export function listPolicyColumns(tableName: string): Promise<ApiResult<PolicyColumnsResponse>> {
  return apiCall<PolicyColumnsResponse>(`${QV_BASE}/policies/columns/${encodeURIComponent(tableName)}`);
}

export function updatePolicyColumn(
  tableName: string, colName: string, classificationLevel: number, visibility: string
): Promise<ApiResult<{ status: string }>> {
  return apiCall<{ status: string }>(
    `${QV_BASE}/policies/columns/${encodeURIComponent(tableName)}/${encodeURIComponent(colName)}`,
    { method: 'PUT', body: JSON.stringify({ classification_level: classificationLevel, default_visibility: visibility }) },
  );
}

export function syncPolicies(): Promise<ApiResult<{ status: string; stats: Record<string, number> }>> {
  return apiCall<{ status: string; stats: Record<string, number> }>(`${QV_BASE}/policies/sync`, {
    method: 'POST',
  });
}
