import { PolicyRoleSummary } from '../types/policies';

export interface PolicyStatement {
  id: string;
  type: 'allow' | 'deny' | 'info' | 'filter';
  text: string;
  section: 'access' | 'operations' | 'domains' | 'filters' | 'info';
}

const CLEARANCE_LABELS: Record<number, string> = {
  1: 'PUBLIC',
  2: 'INTERNAL',
  3: 'RESTRICTED',
  4: 'CONFIDENTIAL',
  5: 'TOP SECRET',
};

function joinList(items: string[]): string {
  if (items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(', ')}, and ${items[items.length - 1]}`;
}

export function generatePolicyStatements(role: PolicyRoleSummary): PolicyStatement[] {
  const statements: PolicyStatement[] = [];

  // Clearance level
  const clLabel = CLEARANCE_LABELS[role.clearance_level] || `Level ${role.clearance_level}`;
  statements.push({
    id: 'clearance',
    type: 'info',
    text: `Has clearance level ${role.clearance_level} (${clLabel})`,
    section: 'info',
  });

  // Allowed tables
  if (role.allowed_tables.length > 0) {
    statements.push({
      id: 'access',
      type: 'allow',
      text: `Can query ${joinList(role.allowed_tables)}`,
      section: 'access',
    });
  } else {
    statements.push({
      id: 'access',
      type: 'deny',
      text: 'No table access configured',
      section: 'access',
    });
  }

  // Denied tables
  if (role.denied_tables.length > 0) {
    statements.push({
      id: 'denied-tables',
      type: 'deny',
      text: `Is denied access to ${joinList(role.denied_tables)}`,
      section: 'access',
    });
  }

  // Denied operations
  if (role.denied_operations.length > 0) {
    statements.push({
      id: 'operations',
      type: 'deny',
      text: `Cannot perform ${joinList(role.denied_operations)} operations`,
      section: 'operations',
    });
  }

  // Domains
  if (role.domains.length > 0) {
    statements.push({
      id: 'domains',
      type: 'info',
      text: `Operates within the ${joinList(role.domains)} domain${role.domains.length > 1 ? 's' : ''}`,
      section: 'domains',
    });
  }

  // Result limit
  if (role.result_limit != null) {
    statements.push({
      id: 'result-limit',
      type: 'deny',
      text: `Query results are limited to ${role.result_limit} rows per request`,
      section: 'info',
    });
  }

  // Row filters
  if (role.row_filters.length > 0) {
    role.row_filters.forEach((rf, i) => {
      const filter = typeof rf === 'string' ? rf : `${rf.table}: ${rf.condition}`;
      const parsed = typeof rf === 'string' ? null : rf;
      let text: string;
      if (parsed) {
        // Make condition more readable
        const cond = parsed.condition
          .replace(/\{\{user\.facility\}\}/g, "the user's facility")
          .replace(/\{\{user\.department\}\}/g, "the user's department");
        text = `Row filter on ${parsed.table} — only rows where ${cond}`;
      } else {
        text = `Row filter: ${filter}`;
      }
      statements.push({
        id: `filter-${i}`,
        type: 'filter',
        text,
        section: 'filters',
      });
    });
  }

  return statements;
}
