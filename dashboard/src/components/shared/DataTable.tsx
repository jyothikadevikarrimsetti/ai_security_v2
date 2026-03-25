interface DataTableProps {
  data: Record<string, unknown>[] | null;
  emptyMessage?: string;
}

function formatHeader(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export function DataTable({ data, emptyMessage = 'No results returned.' }: DataTableProps) {
  if (!Array.isArray(data) || data.length === 0) {
    return (
      <div className="text-sm text-gray-500 dark:text-gray-400 py-4 text-center">
        {emptyMessage}
      </div>
    );
  }

  const columns = Object.keys(data[0]);

  return (
    <div className="overflow-x-auto border border-gray-200 dark:border-gray-700 rounded-lg">
      <table className="w-full text-sm text-left">
        <thead>
          <tr className="bg-gray-100 dark:bg-gray-800">
            {columns.map((col) => (
              <th
                key={col}
                className="px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-gray-400 whitespace-nowrap"
              >
                {formatHeader(col)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr
              key={i}
              className={
                i % 2 === 0
                  ? 'bg-white dark:bg-gray-900'
                  : 'bg-gray-50 dark:bg-gray-800/50'
              }
            >
              {columns.map((col) => (
                <td
                  key={col}
                  className="px-4 py-2 text-gray-800 dark:text-gray-200 whitespace-nowrap"
                >
                  {formatValue(row[col])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {data.length > 100 && (
        <div className="px-4 py-2 text-xs text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
          Showing {data.length} rows
        </div>
      )}
    </div>
  );
}
