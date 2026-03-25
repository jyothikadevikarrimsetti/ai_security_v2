import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { pipelineEmbed } from '../../api/xensql';
import { EmbedResponse } from '../../types/xensql';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

type Mode = 'single' | 'batch';

export const PipelineEmbedPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<EmbedResponse>();

  const [mode, setMode] = useState<Mode>('single');
  const [text, setText] = useState('');
  const [textsRaw, setTextsRaw] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (mode === 'single') {
      execute(() => pipelineEmbed({ text, batch: false }));
    } else {
      const texts = textsRaw
        .split('\n')
        .map((t) => t.trim())
        .filter(Boolean);
      execute(() => pipelineEmbed({ texts, batch: true }));
    }
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Pipeline Embed</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          {/* Mode Toggle */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Mode</label>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setMode('single')}
                className={`px-4 py-2 text-sm rounded-lg font-medium transition-colors ${
                  mode === 'single'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'
                }`}
              >
                Single
              </button>
              <button
                type="button"
                onClick={() => setMode('batch')}
                className={`px-4 py-2 text-sm rounded-lg font-medium transition-colors ${
                  mode === 'batch'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'
                }`}
              >
                Batch
              </button>
            </div>
          </div>

          {mode === 'single' ? (
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Text <span className="text-red-500 ml-1">*</span>
              </label>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Enter text to embed..."
                required
                rows={4}
                className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              />
            </div>
          ) : (
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Texts <span className="text-red-500 ml-1">*</span>
                <span className="text-xs text-gray-400 dark:text-gray-500 ml-2">(one per line)</span>
              </label>
              <textarea
                value={textsRaw}
                onChange={(e) => setTextsRaw(e.target.value)}
                placeholder={"First text to embed\nSecond text to embed\nThird text to embed"}
                required
                rows={6}
                className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              />
            </div>
          )}

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Embedding...
              </span>
            ) : (
              'Submit'
            )}
          </button>
        </form>
      </div>

      {/* Error Display */}
      {result?.error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
          <p className="text-sm text-red-700 dark:text-red-300">{result.error}</p>
        </div>
      )}

      {/* Response Section */}
      {data && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
          <h3 className="text-lg font-medium mb-4">Response</h3>

          <div className="grid grid-cols-2 gap-4 mb-4">
            {data.dimensions != null && (
              <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3">
                <p className="text-xs text-gray-500 dark:text-gray-400">Dimensions</p>
                <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{data.dimensions}</p>
              </div>
            )}
            {data.count != null && (
              <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3">
                <p className="text-xs text-gray-500 dark:text-gray-400">Embeddings Count</p>
                <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">{data.count}</p>
              </div>
            )}
          </div>

          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
