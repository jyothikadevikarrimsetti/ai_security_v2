export interface GatewayQueryRequest {
  question: string;
  jwt_token: string;
}

export interface PreModelChecks {
  injection_blocked: boolean;
  injection_risk_score: number;
  injection_flags: string[];
  probing_detected: boolean;
  probing_score: number;
  behavioral_anomaly_score: number;
  behavioral_flags: string[];
  threat_level: string;
  threat_category: string | null;
}

export interface PostModelChecks {
  validation_decision: string;
  hallucination_detected: boolean;
  hallucinated_identifiers: string[];
  gate_results: Record<string, string>;
  violations: any[];
  rewrites_applied: string[];
}

export interface ExecutionResult {
  rows_returned: number;
  execution_latency_ms: number;
  sanitization_applied: boolean;
  resource_limits_hit: boolean;
  data: any | null;
}

export interface SecuritySummary {
  zones_passed: string[];
  threat_level: string;
  validation_result: string;
  execution_status: string;
  audit_trail_id: string;
  pre_model: PreModelChecks;
  post_model: PostModelChecks;
  execution: ExecutionResult | null;
}

export interface GatewayQueryResponse {
  request_id: string;
  sql: string | null;
  results: any | null;
  security_summary: SecuritySummary;
  audit_id: string;
  error: string | null;
  blocked_reason: string | null;
}

export interface GatewayHealthResponse {
  status: string;
  service: string;
  version: string;
  components: Record<string, string>;
}

export interface ComplianceReportResponse {
  success: boolean;
  error: string | null;
  report: any;
}

export interface StandardsResponse {
  standards: { id: string; name: string; description: string }[];
}

export interface DashboardResponse {
  time_range_days: number;
  total_violations: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  generated_at: string;
}

export interface ThreatAnalysisResponse {
  time_range_days: number;
  user_id: string | null;
  total_threats: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  top_users: Record<string, number>;
  recent_events: any[];
  generated_at: string;
}

export interface PatternsResponse {
  version: string;
  total_patterns: number;
  enabled: number;
  disabled: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

export interface AlertsResponse {
  alerts: any[];
  total: number;
  limit: number;
  offset: number;
}

export interface AlertActionResponse {
  status: string;
  alert_id: string;
  message: string | null;
  acknowledged_at?: string;
  resolved_at?: string;
}
