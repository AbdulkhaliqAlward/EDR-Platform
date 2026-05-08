import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Shield } from 'lucide-react';
import { Suspense, lazy } from 'react';
import { ToastProvider } from './components';
import { CommandApprovalProvider } from './components/CommandApprovalProvider';
import { authApi } from './api/client';
import { PlatformAppShell } from './layout/PlatformAppShell';

import './index.css';

// Lazy load pages for better performance
const EssentialPlatform = lazy(() => import('./pages/EssentialPlatform'));
const SecurityPosture = lazy(() => import('./pages/Dashboard'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Rules = lazy(() => import('./pages/Rules'));
const Stats = lazy(() => import('./pages/Stats'));
const Login = lazy(() => import('./pages/Login'));
const Settings = lazy(() => import('./pages/Settings'));
const Endpoints = lazy(() => import('./pages/Endpoints'));
const EndpointDetail = lazy(() => import('./pages/EndpointDetail'));
const Events = lazy(() => import('./pages/Events'));
const EndpointRisk = lazy(() => import('./pages/EndpointRisk'));
const Threats = lazy(() => import('./pages/Threats'));
const AuditLogs = lazy(() => import('./pages/AuditLogs'));
const EnrollmentTokens = lazy(() => import('./pages/EnrollmentTokens'));
const SecurityEvents = lazy(() => import('./pages/SecurityEvents'));
const ActionCenter = lazy(() => import('./pages/ActionCenter'));
const AgentDeployment = lazy(() => import('./pages/AgentDeployment'));
const SystemLayout = lazy(() => import('./pages/SystemLayout'));
const ReportPreviewPage = lazy(() => import('./pages/ReportPreviewPage'));

const DashboardsLayout = lazy(() => import('./pages/parity/DashboardsLayout'));
const DashboardEndpointPage = lazy(() => import('./pages/parity/dashboardPages').then((m) => ({ default: m.DashboardEndpointPage })));
const DashboardCloudPage = lazy(() => import('./pages/parity/dashboardPages').then((m) => ({ default: m.DashboardCloudPage })));
const DashboardAuditRedirect = lazy(() => import('./pages/parity/dashboardPages').then((m) => ({ default: m.DashboardAuditRedirect })));
const DashboardEndpointCompliancePage = lazy(() => import('./pages/parity/dashboardPages').then((m) => ({ default: m.DashboardEndpointCompliancePage })));
const DashboardVerdictCloudPage = lazy(() => import('./pages/parity/dashboardPages').then((m) => ({ default: m.DashboardVerdictCloudPage })));
const DashboardReportsPage = lazy(() => import('./pages/parity/dashboardPages').then((m) => ({ default: m.DashboardReportsPage })));
const SocCorrelationPage = lazy(() => import('./pages/SocCorrelation'));

const SecurityEndpointZeroTrustPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.SecurityEndpointZeroTrustPage })));
const SecuritySiemPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.SecuritySiemPage })));
const ManagedSecurityOverviewPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagedSecurityOverviewPage })));
const ManagedSecurityIncidentsPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagedSecurityIncidentsPage })));
const ItsmPlaybooksPage = lazy(() => import('./pages/automation/PlaybooksPage').then((m) => ({ default: m.PlaybooksPage })));
const ItsmAutomationsPage = lazy(() => import('./pages/automation/AutomationRulesPage').then((m) => ({ default: m.AutomationRulesPage })));
const ManagementNetworkPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementNetworkPage })));
const ManagementStaffPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementStaffPage })));
const ManagementAccountPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementAccountPage })));
const ManagementRmmPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementRmmPage })));
const ManagementVulnPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementVulnPage })));
const ManagementAppControlPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementAppControlPage })));
const ManagementLicensesPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementLicensesPage })));
const ManagementBillingPage = lazy(() => import('./pages/parity/paritySectionPages').then((m) => ({ default: m.ManagementBillingPage })));

const SettingsUserProfile = lazy(() => import('./components/settings/UserProfile'));
const SettingsSystemConfiguration = lazy(() => import('./pages/settings/SystemConfiguration'));
const SettingsContextPolicies = lazy(() => import('./pages/settings/ContextPolicies'));
const SettingsReliabilityHealth = lazy(() => import('./pages/settings/ReliabilityHealth'));
const SettingsSignaturesManagement = lazy(() => import('./pages/settings/SignaturesManagement'));
const SettingsAccessManagement = lazy(() => import('./components/settings/AccessManagement'));
const SettingsRBACMatrix = lazy(() => import('./components/settings/RBACMatrix'));

function SettingsTabFallback() {
    return (
        <div className="flex items-center justify-center py-24 text-gray-500 dark:text-gray-400 text-sm">
            Loading…
        </div>
    );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30000,
    },
  },
});

// Loading spinner for Suspense
function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
    </div>
  );
}

// Check if user is authenticated
function isAuthenticated() {
  return authApi.isAuthenticated();
}

// Protected Route component
function ProtectedRoute({ children, roles }: { children: React.ReactNode; roles?: string[] }) {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }

  if (roles && roles.length > 0 && !authApi.hasRole(roles)) {
    return (
      <div className="card text-center py-12">
        <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
          Access Denied
        </h3>
        <p className="text-gray-500">You don't have permission to view this page.</p>
      </div>
    );
  }

  return <>{children}</>;
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <PlatformAppShell>
      <Suspense fallback={<PageLoader />}>
        {children}
      </Suspense>
    </PlatformAppShell>
  );
}

function AppRoutes() {
  return (
    <Routes>
      {/* Login page without layout */}
      <Route path="/login" element={
        <Suspense fallback={<PageLoader />}>
          <Login />
        </Suspense>
      } />

      {/* Report Preview — standalone page, no sidebar/layout */}
      <Route path="/report-preview" element={
        <Suspense fallback={<PageLoader />}>
          <ReportPreviewPage />
        </Suspense>
      } />

      {/* Main app with layout */}
      <Route path="/*" element={
        <Layout>
          <Routes>
            {/* Dashboard & Stats: all authenticated users */}
            <Route path="/" element={
              <ProtectedRoute>
                <Navigate to="/dashboards/service" replace />
              </ProtectedRoute>
            } />
            <Route path="/platform" element={
              <ProtectedRoute>
                <EssentialPlatform />
              </ProtectedRoute>
            } />
            <Route path="/stats" element={
              <ProtectedRoute>
                <Stats />
              </ProtectedRoute>
            } />

            {/* Alerts: alerts:read → all roles */}
            <Route path="/alerts" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <Alerts />
              </ProtectedRoute>
            } />

            {/* Events: alerts:read (server guard) → all roles */}
            <Route path="/events" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <Events />
              </ProtectedRoute>
            } />

            {/* Endpoints: endpoints:read → all roles */}
            <Route path="/endpoints" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <Endpoints />
              </ProtectedRoute>
            } />

            {/* Risk Intelligence: alerts:read → all roles */}
            <Route path="/endpoint-risk" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <EndpointRisk />
              </ProtectedRoute>
            } />

            {/* Threats: alerts:read → all roles */}
            <Route path="/threats" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <Threats />
              </ProtectedRoute>
            } />

            {/* Rules: rules:read → admin, security, analyst, viewer */}
            <Route path="/rules" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'viewer']}>
                <Rules />
              </ProtectedRoute>
            } />

            {/* Action Center: responses:read → admin, security, analyst, operations */}
            <Route path="/responses" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations']}>
                <ActionCenter />
              </ProtectedRoute>
            } />

            {/* Audit Logs: audit:read → admin, security */}
            <Route path="/audit" element={
              <Navigate to="/system/audit-logs" replace />
            } />

            {/* Enrollment Tokens: tokens:read → all roles */}
            <Route path="/tokens" element={
              <Navigate to="/security/tokens" replace />
            } />

            {/* Agent Deployment: agents:read → admin, security, operations */}
            <Route path="/deploy" element={
              <Navigate to="/management/agent-deploy" replace />
            } />

            {/* Settings: keep only platform settings (dashboard/admin settings live here) */}
            <Route
                path="/settings"
                element={
                    <ProtectedRoute>
                        <Settings />
                    </ProtectedRoute>
                }
            >
                <Route index element={<Navigate to="system" replace />} />
                <Route
                    path="profile"
                    element={<Navigate to="/system/profile" replace />}
                />
                <Route
                    path="system"
                    element={
                        <Suspense fallback={<SettingsTabFallback />}>
                            <SettingsSystemConfiguration />
                        </Suspense>
                    }
                />
                <Route
                    path="context"
                    element={<Navigate to="/management/context-policies" replace />}
                />
                <Route
                    path="reliability"
                    element={<Navigate to="/system/reliability-health" replace />}
                />
                <Route
                    path="users"
                    element={<Navigate to="/system/access/users" replace />}
                />
                <Route
                    path="roles"
                    element={<Navigate to="/system/access/roles" replace />}
                />
            </Route>

            {/* System hub */}
            <Route path="/system" element={<ProtectedRoute><SystemLayout /></ProtectedRoute>}>
              <Route index element={<Navigate to="profile" replace />} />
              <Route path="platform-settings" element={<Navigate to="/settings/system" replace />} />
              <Route path="profile" element={<ProtectedRoute><SettingsUserProfile /></ProtectedRoute>} />
              <Route path="access/users" element={<ProtectedRoute><SettingsAccessManagement /></ProtectedRoute>} />
              <Route
                path="access/roles"
                element={
                  <ProtectedRoute roles={['admin', 'security']}>
                    <SettingsRBACMatrix />
                  </ProtectedRoute>
                }
              />
              <Route path="security/tokens" element={
                <Navigate to="/security/tokens" replace />
              } />
              <Route path="audit-logs" element={
                <ProtectedRoute roles={['admin', 'security']}>
                  <AuditLogs />
                </ProtectedRoute>
              } />
              <Route path="reliability-health" element={
                <ProtectedRoute>
                  <Suspense fallback={<SettingsTabFallback />}>
                    <SettingsReliabilityHealth />
                  </Suspense>
                </ProtectedRoute>
              } />
              <Route path="signatures" element={
                <ProtectedRoute>
                  <Suspense fallback={<SettingsTabFallback />}>
                    <SettingsSignaturesManagement />
                  </Suspense>
                </ProtectedRoute>
              } />
            </Route>

            {/* Platform hub (APIs on Sigma `/api/v1/...`; 404 → silent mock in UI) */}
            <Route path="/dashboards" element={
              <ProtectedRoute>
                <DashboardsLayout />
              </ProtectedRoute>
            }>
              <Route index element={<Navigate to="service" replace />} />
              <Route path="service" element={<SecurityPosture />} />
              <Route path="endpoint" element={<DashboardEndpointPage />} />
              <Route path="cloud" element={<DashboardCloudPage />} />
              <Route path="audit" element={<DashboardAuditRedirect />} />
              <Route path="endpoint-compliance" element={<DashboardEndpointCompliancePage />} />
              <Route path="ctem-compliance" element={<Navigate to="endpoint" replace />} />
              <Route path="ctem" element={<Navigate to="endpoint" replace />} />
              <Route path="verdict-cloud" element={<DashboardVerdictCloudPage />} />
              <Route path="reports" element={<DashboardReportsPage />} />
              <Route path="roi" element={<Navigate to="endpoint" replace />} />
            </Route>

            <Route path="/security" element={<Navigate to="/security/endpoint-zero-trust" replace />} />
            <Route path="/security/endpoint-zero-trust" element={<ProtectedRoute><SecurityEndpointZeroTrustPage /></ProtectedRoute>} />
            <Route path="/security/siem-x" element={<ProtectedRoute><SecuritySiemPage /></ProtectedRoute>} />
            <Route path="/security/cloud-zero-trust" element={<Navigate to="/security/endpoint-zero-trust" replace />} />
            <Route path="/security/threat-labs" element={<Navigate to="/security/siem-x" replace />} />
            <Route path="/security/tokens" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <EnrollmentTokens />
              </ProtectedRoute>
            } />

            {/* Security Events: audit:read → admin, security */}
            <Route path="/security/events" element={
              <ProtectedRoute roles={['admin', 'security']}>
                <SecurityEvents />
              </ProtectedRoute>
            } />

            <Route path="/managed-security" element={<Navigate to="/managed-security/overview" replace />} />
            <Route path="/managed-security/overview" element={<ProtectedRoute><ManagedSecurityOverviewPage /></ProtectedRoute>} />
            <Route path="/managed-security/incidents" element={<ProtectedRoute><ManagedSecurityIncidentsPage /></ProtectedRoute>} />
            <Route path="/managed-security/sla" element={<Navigate to="/managed-security/overview" replace />} />

            <Route path="/itsm/tickets" element={<Navigate to="/itsm/playbooks" replace />} />
            <Route path="/itsm/playbooks" element={<ProtectedRoute><ItsmPlaybooksPage /></ProtectedRoute>} />
            <Route path="/itsm/automations" element={<ProtectedRoute><ItsmAutomationsPage /></ProtectedRoute>} />
            <Route path="/itsm/integrations" element={<Navigate to="/itsm/playbooks" replace />} />

            {/* SOC extensions */}
            <Route path="/soc/correlation" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <SocCorrelationPage />
              </ProtectedRoute>
            } />
            <Route path="/soc/vulnerability" element={<ProtectedRoute><ManagementVulnPage /></ProtectedRoute>} />

            <Route path="/management/devices/:agentId" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <EndpointDetail />
              </ProtectedRoute>
            } />
            <Route path="/management/devices" element={
              <ProtectedRoute roles={['admin', 'security', 'analyst', 'operations', 'viewer']}>
                <Endpoints />
              </ProtectedRoute>
            } />
            <Route path="/endpoints" element={<Navigate to="/management/devices" replace />} />
            <Route path="/management/profiles" element={<Navigate to="/management/devices" replace />} />
            <Route path="/management/rmm" element={<ProtectedRoute><ManagementRmmPage /></ProtectedRoute>} />
            <Route path="/management/patch" element={<Navigate to="/management/devices" replace />} />
            <Route path="/management/vulnerability" element={<Navigate to="/soc/vulnerability" replace />} />
            <Route path="/management/network" element={<ProtectedRoute><ManagementNetworkPage /></ProtectedRoute>} />
            <Route path="/management/app-control" element={<ProtectedRoute><ManagementAppControlPage /></ProtectedRoute>} />
            <Route path="/management/application-control" element={<ProtectedRoute><ManagementAppControlPage /></ProtectedRoute>} />
            <Route path="/management/staff" element={<ProtectedRoute><ManagementStaffPage /></ProtectedRoute>} />
            <Route path="/system/account" element={<ProtectedRoute><ManagementAccountPage /></ProtectedRoute>} />
             <Route path="/management/account" element={<Navigate to="/system/account" replace />} />
            <Route path="/management/users" element={<Navigate to="/management/devices" replace />} />
            <Route path="/management/licenses" element={<ProtectedRoute><ManagementLicensesPage /></ProtectedRoute>} />
            <Route path="/management/billing" element={<ProtectedRoute><ManagementBillingPage /></ProtectedRoute>} />

            <Route path="/management/agent-deploy" element={
              <ProtectedRoute roles={['admin', 'security', 'operations']}>
                <AgentDeployment />
              </ProtectedRoute>
            } />
            <Route path="/management/agent-profiles" element={<Navigate to="/management/devices" replace />} />
            <Route path="/management/context-policies" element={
              <ProtectedRoute>
                {/* This is an admin-ish control surface; kept under Management per requirements. */}
                <Suspense fallback={<SettingsTabFallback />}>
                  <SettingsContextPolicies />
                </Suspense>
              </ProtectedRoute>
            } />
          </Routes>
        </Layout>
      } />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <CommandApprovalProvider>
          <BrowserRouter>
            <AppRoutes />
          </BrowserRouter>
        </CommandApprovalProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}


