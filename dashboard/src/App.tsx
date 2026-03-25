import { useState } from 'react';
import { ThemeProvider } from './hooks/useTheme';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { LoginPage } from './pages/LoginPage';
import { PolicyConfigPage } from './pages/PolicyConfigPage';
import MainLayout from './components/layout/MainLayout';
import { PanelId } from './config/endpoints';

// Panel components
import { GatewayQueryPanel } from './panels/queryvault/GatewayQueryPanel';
import { QVHealthPanel } from './panels/queryvault/QVHealthPanel';
import { ComplianceReportPanel } from './panels/queryvault/ComplianceReportPanel';
import { ComplianceStandardsPanel } from './panels/queryvault/ComplianceStandardsPanel';
import { ComplianceDashboardPanel } from './panels/queryvault/ComplianceDashboardPanel';
import { ThreatAnalysisPanel } from './panels/queryvault/ThreatAnalysisPanel';
import { ThreatPatternsPanel } from './panels/queryvault/ThreatPatternsPanel';
import { AlertsPanel } from './panels/queryvault/AlertsPanel';
import { RolePoliciesPanel } from './panels/queryvault/RolePoliciesPanel';
import { TableClassificationPanel } from './panels/queryvault/TableClassificationPanel';
import { PipelineQueryPanel } from './panels/xensql/PipelineQueryPanel';
import { PipelineEmbedPanel } from './panels/xensql/PipelineEmbedPanel';
import { SchemaCrawlPanel } from './panels/xensql/SchemaCrawlPanel';
import { SchemaCatalogPanel } from './panels/xensql/SchemaCatalogPanel';
import { XenSQLHealthPanel } from './panels/xensql/XenSQLHealthPanel';

const PANEL_MAP: Record<PanelId, React.FC> = {
  'qv-gateway-query': GatewayQueryPanel,
  'qv-gateway-health': QVHealthPanel,
  'qv-compliance-report': ComplianceReportPanel,
  'qv-compliance-standards': ComplianceStandardsPanel,
  'qv-compliance-dashboard': ComplianceDashboardPanel,
  'qv-threat-analysis': ThreatAnalysisPanel,
  'qv-threat-patterns': ThreatPatternsPanel,
  'qv-alerts': AlertsPanel,
  'qv-policy-roles': RolePoliciesPanel,
  'qv-policy-tables': TableClassificationPanel,
  'xensql-pipeline-query': PipelineQueryPanel,
  'xensql-pipeline-embed': PipelineEmbedPanel,
  'xensql-schema-crawl': SchemaCrawlPanel,
  'xensql-schema-catalog': SchemaCatalogPanel,
  'xensql-health': XenSQLHealthPanel,
};

type AppMode = 'dashboard' | 'policies';

function AppContent() {
  const { auth } = useAuth();
  const [activePanel, setActivePanel] = useState<PanelId>('qv-gateway-query');
  const [mode, setMode] = useState<AppMode>('dashboard');

  if (!auth) return <LoginPage />;

  if (mode === 'policies') {
    return <PolicyConfigPage onBack={() => setMode('dashboard')} />;
  }

  const PanelComponent = PANEL_MAP[activePanel];

  return (
    <MainLayout
      activePanel={activePanel}
      onSelectPanel={setActivePanel}
      onConfigurePolicies={() => setMode('policies')}
    >
      {PanelComponent ? <PanelComponent /> : <div className="text-gray-500">Panel not found</div>}
    </MainLayout>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}
