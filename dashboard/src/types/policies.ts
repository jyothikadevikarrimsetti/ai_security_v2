export interface PolicyRoleSummary {
  name: string;
  clearance_level: number;
  domain: string;
  bound_policies: string[];
  result_limit: number | null;
  allowed_tables: string[];
  denied_tables: string[];
  denied_operations: string[];
  row_filters: ({ table: string; condition: string } | string)[];
  domains: string[];
}

export interface PolicyRolesResponse {
  roles: PolicyRoleSummary[];
}

export interface RolePolicyUpdate {
  allowed_tables: string[];
  denied_tables: string[];
  denied_operations: string[];
  row_filters: { table: string; condition: string }[];
  domains: string[];
  result_limit?: number | null;
}

export interface PolicyTableSummary {
  name: string;
  sensitivity_level: number;
  domain: string;
  column_count: number;
}

export interface PolicyTablesResponse {
  tables: PolicyTableSummary[];
}

export interface PolicyColumn {
  name: string;
  data_type: string;
  classification_level: number;
  default_visibility: string;
  is_pii: boolean;
}

export interface PolicyColumnsResponse {
  table: string;
  columns: PolicyColumn[];
}
