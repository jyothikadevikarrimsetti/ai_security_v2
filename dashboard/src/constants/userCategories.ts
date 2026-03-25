import React from 'react';
import {
  Stethoscope,
  HeartPulse,
  Receipt,
  Users,
  Monitor,
  ShieldCheck,
  Microscope,
  UserX,
  Building2,
  FlaskConical,
} from 'lucide-react';

export const CATEGORY_ORDER = [
  'Physician',
  'Nurse',
  'Billing',
  'HR',
  'IT',
  'Compliance',
  'Research',
  'Terminated',
];

export const CATEGORY_ICON: Record<string, React.FC<{ className?: string }>> = {
  Physician: Stethoscope,
  Nurse: HeartPulse,
  Billing: Receipt,
  HR: Users,
  IT: Monitor,
  Compliance: ShieldCheck,
  Research: Microscope,
  Terminated: UserX,
};

export const CATEGORY_COLOR: Record<string, string> = {
  Physician: 'text-blue-600 dark:text-blue-400',
  Nurse: 'text-pink-600 dark:text-pink-400',
  Billing: 'text-emerald-600 dark:text-emerald-400',
  HR: 'text-purple-600 dark:text-purple-400',
  IT: 'text-orange-600 dark:text-orange-400',
  Compliance: 'text-teal-600 dark:text-teal-400',
  Research: 'text-indigo-600 dark:text-indigo-400',
  Terminated: 'text-red-600 dark:text-red-400',
};

// ── Domain grouping (for role-based views) ──────────────────

export const DOMAIN_GROUP_ORDER = ['CLINICAL', 'FINANCIAL', 'ADMINISTRATIVE', 'RESEARCH', 'COMPLIANCE', 'IT_OPERATIONS'];

export const DOMAIN_GROUP_LABELS: Record<string, string> = {
  CLINICAL: 'Clinical',
  FINANCIAL: 'Financial',
  ADMINISTRATIVE: 'Administrative',
  RESEARCH: 'Research',
  COMPLIANCE: 'Compliance',
  IT_OPERATIONS: 'IT Operations',
  '': 'Unconfigured',
};

export const DOMAIN_GROUP_COLORS: Record<string, string> = {
  CLINICAL: 'border-blue-200 dark:border-blue-800',
  FINANCIAL: 'border-emerald-200 dark:border-emerald-800',
  ADMINISTRATIVE: 'border-purple-200 dark:border-purple-800',
  RESEARCH: 'border-indigo-200 dark:border-indigo-800',
  COMPLIANCE: 'border-teal-200 dark:border-teal-800',
  IT_OPERATIONS: 'border-orange-200 dark:border-orange-800',
  '': 'border-gray-200 dark:border-gray-700',
};

export const DOMAIN_GROUP_TEXT_COLORS: Record<string, string> = {
  CLINICAL: 'text-blue-600 dark:text-blue-400',
  FINANCIAL: 'text-emerald-600 dark:text-emerald-400',
  ADMINISTRATIVE: 'text-purple-600 dark:text-purple-400',
  RESEARCH: 'text-indigo-600 dark:text-indigo-400',
  COMPLIANCE: 'text-teal-600 dark:text-teal-400',
  IT_OPERATIONS: 'text-orange-600 dark:text-orange-400',
  '': 'text-gray-500 dark:text-gray-400',
};

export const DOMAIN_ICON: Record<string, React.FC<{ className?: string }>> = {
  CLINICAL: Stethoscope,
  FINANCIAL: Receipt,
  ADMINISTRATIVE: Building2,
  RESEARCH: FlaskConical,
  COMPLIANCE: ShieldCheck,
  IT_OPERATIONS: Monitor,
};

// ── Clearance badges ─────────────────────────────────────────

export const CLEARANCE_BADGE: Record<number, { label: string; color: string }> = {
  1: { label: 'L1 Public', color: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400' },
  2: { label: 'L2 Internal', color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400' },
  3: { label: 'L3 Confidential', color: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-400' },
  4: { label: 'L4 Highly Conf.', color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-400' },
  5: { label: 'L5 Restricted', color: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400' },
};
