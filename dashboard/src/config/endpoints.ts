export const XENSQL_BASE = '/xensql/api/v1';
export const QV_BASE = '/queryvault/api/v1';

export type PanelId =
  | 'xensql-pipeline-query' | 'xensql-pipeline-embed' | 'xensql-schema-crawl' | 'xensql-schema-catalog' | 'xensql-health'
  | 'qv-gateway-query' | 'qv-gateway-health' | 'qv-compliance-report' | 'qv-compliance-standards' | 'qv-compliance-dashboard'
  | 'qv-threat-analysis' | 'qv-threat-patterns' | 'qv-alerts'
  | 'qv-policy-roles' | 'qv-policy-tables';

export interface NavItem { id: PanelId; label: string; method: 'GET' | 'POST' }
export interface NavGroup { label: string; items: NavItem[] }
export interface NavSection { product: string; port: number; groups: NavGroup[] }

export const NAVIGATION: NavSection[] = [
  {
    product: 'XenSQL', port: 8900,
    groups: [
      { label: 'Pipeline', items: [
        { id: 'xensql-pipeline-query', label: 'Query (NL→SQL)', method: 'POST' },
        { id: 'xensql-pipeline-embed', label: 'Embed Text', method: 'POST' },
      ]},
      { label: 'Schema', items: [
        { id: 'xensql-schema-crawl', label: 'Crawl', method: 'POST' },
        { id: 'xensql-schema-catalog', label: 'Catalog', method: 'GET' },
      ]},
      { label: 'System', items: [
        { id: 'xensql-health', label: 'Health', method: 'GET' },
      ]},
    ],
  },
  {
    product: 'QueryVault', port: 8950,
    groups: [
      { label: 'Gateway', items: [
        { id: 'qv-gateway-query', label: 'Secure Query', method: 'POST' },
        { id: 'qv-gateway-health', label: 'Health', method: 'GET' },
      ]},
      { label: 'Compliance', items: [
        { id: 'qv-compliance-report', label: 'Report', method: 'GET' },
        { id: 'qv-compliance-standards', label: 'Standards', method: 'GET' },
        { id: 'qv-compliance-dashboard', label: 'Dashboard', method: 'GET' },
      ]},
      { label: 'Threats', items: [
        { id: 'qv-threat-analysis', label: 'Analysis', method: 'GET' },
        { id: 'qv-threat-patterns', label: 'Patterns', method: 'GET' },
      ]},
      { label: 'Alerts', items: [
        { id: 'qv-alerts', label: 'Alerts', method: 'GET' },
      ]},
      { label: 'Policies', items: [
        { id: 'qv-policy-roles', label: 'Role Policies', method: 'GET' },
        { id: 'qv-policy-tables', label: 'Table Classification', method: 'GET' },
      ]},
    ],
  },
];
