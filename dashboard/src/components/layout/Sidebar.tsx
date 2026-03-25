import { useState } from 'react';
import { Database, Shield, ChevronDown, ChevronRight } from 'lucide-react';
import { NAVIGATION, PanelId } from '../../config/endpoints';

interface SidebarProps {
  activePanel: PanelId;
  onSelectPanel: (id: PanelId) => void;
}

export default function Sidebar({ activePanel, onSelectPanel }: SidebarProps) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const toggleGroup = (key: string) => {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <aside className="w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-700 overflow-y-auto flex-shrink-0">
      {NAVIGATION.map((section) => {
        const Icon = section.product === 'XenSQL' ? Database : Shield;
        return (
          <div key={section.product} className="py-3">
            {/* Product header */}
            <div className="flex items-center gap-2 px-4 pb-2">
              <Icon className="w-4 h-4 text-gray-500 dark:text-gray-400" />
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
                {section.product}
              </span>
              <span className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400">
                :{section.port}
              </span>
            </div>

            {/* Groups */}
            {section.groups.map((group) => {
              const groupKey = `${section.product}-${group.label}`;
              const isCollapsed = collapsed[groupKey] ?? false;

              return (
                <div key={groupKey}>
                  <button
                    onClick={() => toggleGroup(groupKey)}
                    className="w-full flex items-center gap-1 px-4 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                  >
                    {isCollapsed ? (
                      <ChevronRight className="w-3.5 h-3.5" />
                    ) : (
                      <ChevronDown className="w-3.5 h-3.5" />
                    )}
                    {group.label}
                  </button>

                  {!isCollapsed && (
                    <div className="ml-2">
                      {group.items.map((item) => {
                        const isActive = activePanel === item.id;
                        return (
                          <button
                            key={item.id}
                            onClick={() => onSelectPanel(item.id)}
                            className={`w-full flex items-center justify-between px-6 py-1.5 text-sm transition-colors ${
                              isActive
                                ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
                                : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800'
                            }`}
                          >
                            <span>{item.label}</span>
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                                item.method === 'GET'
                                  ? 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400'
                                  : 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400'
                              }`}
                            >
                              {item.method}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}
    </aside>
  );
}
