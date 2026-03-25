import React, { useState, useCallback } from 'react';

interface JsonViewerProps {
  rawJson: string;
  label?: string;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({ rawJson, label = 'Response JSON' }) => {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const formatted = (() => {
    try {
      return JSON.stringify(JSON.parse(rawJson), null, 2);
    } catch {
      return rawJson;
    }
  })();

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback: ignored
    }
  }, [formatted]);

  return (
    <div className="border border-gray-300 dark:border-gray-600 rounded-md mt-2">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="w-full flex items-center justify-between px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-t-md"
      >
        <span>{label}</span>
        <span className="text-xs">{open ? '▲ Collapse' : '▼ Expand'}</span>
      </button>

      {open && (
        <div className="relative">
          <button
            type="button"
            onClick={handleCopy}
            className="absolute top-2 right-2 px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-500"
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <pre className="p-3 overflow-auto max-h-96 text-xs font-mono bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 rounded-b-md">
            <code>{formatted}</code>
          </pre>
        </div>
      )}
    </div>
  );
};
