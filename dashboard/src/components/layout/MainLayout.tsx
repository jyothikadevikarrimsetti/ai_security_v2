import { ReactNode } from 'react';
import TopBar from './TopBar';
import Sidebar from './Sidebar';
import { PanelId } from '../../config/endpoints';

interface MainLayoutProps {
  activePanel: PanelId;
  onSelectPanel: (id: PanelId) => void;
  onConfigurePolicies?: () => void;
  children: ReactNode;
}

export default function MainLayout({ activePanel, onSelectPanel, onConfigurePolicies, children }: MainLayoutProps) {
  return (
    <div className="h-screen flex flex-col bg-gray-50 dark:bg-gray-950">
      <TopBar onConfigurePolicies={onConfigurePolicies} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar activePanel={activePanel} onSelectPanel={onSelectPanel} />
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
