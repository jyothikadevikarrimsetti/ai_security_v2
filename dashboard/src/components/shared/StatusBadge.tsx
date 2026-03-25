import React from 'react';

interface StatusBadgeProps {
  value: string;
}

type ColorScheme = 'green' | 'yellow' | 'red' | 'blue' | 'gray';

function resolveColor(value: string): ColorScheme {
  const upper = value.toUpperCase();

  // Green values
  const greenValues = ['OK', 'GENERATED', 'PASS', 'HEALTHY', 'NONE', 'APPROVED', 'SUCCESS'];
  if (greenValues.includes(upper)) return 'green';
  // HIGH is green only for confidence context; handled below
  if (upper === 'HIGH') return 'green';

  // Yellow values
  const yellowValues = ['DEGRADED', 'MEDIUM', 'AMBIGUOUS', 'ACKNOWLEDGED', 'WARN'];
  if (yellowValues.includes(upper)) return 'yellow';

  // Red values
  const redValues = ['ERROR', 'CRITICAL', 'FAIL', 'BLOCKED', 'UNHEALTHY', 'OPEN'];
  if (redValues.includes(upper)) return 'red';

  // Blue values
  const blueValues = ['LOW', 'INFO', 'RESOLVED'];
  if (blueValues.includes(upper)) return 'blue';

  return 'gray';
}

const colorClasses: Record<ColorScheme, string> = {
  green: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  yellow: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  red: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  blue: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  gray: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({ value }) => {
  const color = resolveColor(value);
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClasses[color]}`}
    >
      {value}
    </span>
  );
};
