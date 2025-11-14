import { createRouter, createWebHistory } from 'vue-router';
import Home from '../views/Home.vue';
import Dashboard from '../views/Dashboard.vue';
import ApplicationDashboard from '../views/ApplicationDashboard.vue';
import ApplicationDetail from '../views/ApplicationDetail.vue';
import Applications from '../views/Applications.vue';
import TeamDashboard from '../views/TeamDashboard.vue';
import Tests from '../views/Tests.vue';
import TestsOverview from '../views/TestsOverview.vue';
import TestBatteries from '../views/TestBatteries.vue';
import TestHarnesses from '../views/TestHarnesses.vue';
import TestSuites from '../views/TestSuites.vue';
import TestLibrary from '../views/TestLibrary.vue';
import Findings from '../views/Findings.vue';
import TestSuiteBuilder from '../views/TestSuiteBuilder.vue';
import TestSuiteDetail from '../views/TestSuiteDetail.vue';
import TestBatteryDetail from '../views/TestBatteryDetail.vue';
import TestHarnessDetail from '../views/TestHarnessDetail.vue';
import Reports from '../views/Reports.vue';
import Policies from '../views/Policies.vue';
import PolicyDetail from '../views/PolicyDetail.vue';
import Insights from '../views/insights/Insights.vue';
import Violations from '../views/Violations.vue';
import History from '../views/History.vue';
import Admin from '../views/Admin.vue';
import ConfigurationValidation from '../views/ConfigurationValidation.vue';
import DistributedSystems from '../views/DistributedSystems.vue';
import DataPipelines from '../views/DataPipelines.vue';
import EphemeralEnvironments from '../views/EphemeralEnvironments.vue';
import ApiSecurity from '../views/ApiSecurity.vue';
import Settings from '../views/Settings.vue';
import Integrations from '../views/Integrations.vue';
import CICDIntegration from '../views/CICDIntegration.vue';
import UserSimulation from '../views/UserSimulation.vue';
import Resources from '../views/Resources.vue';
import Contracts from '../views/Contracts.vue';
import Datasets from '../views/Datasets.vue';
import TicketingIntegrations from '../views/TicketingIntegrations.vue';
import SLAManagement from '../views/SLAManagement.vue';
import Compliance from '../views/Compliance.vue';
import UnifiedFindings from '../views/UnifiedFindings.vue';
import HowItWorks from '../views/HowItWorks.vue';
import Repos from '../views/Repos.vue';
import NotFound from '../views/NotFound.vue';
import AccessDenied from '../views/AccessDenied.vue';
import RLSCLS from '../views/RLSCLS.vue';
import PolicyValidation from '../views/PolicyValidation.vue';
import IdentityProviders from '../views/IdentityProviders.vue';
import NetworkPolicies from '../views/NetworkPolicies.vue';
import APIGateway from '../views/APIGateway.vue';
import DLP from '../views/DLP.vue';
import NIST800207 from '../views/NIST800207.vue';
import CICDSecurityGates from '../views/CICDSecurityGates.vue';
import TestConfigurations from '../views/TestConfigurations.vue';
import TestHistory from '../views/TestHistory.vue';
import ComplianceTrends from '../views/ComplianceTrends.vue';
import DeveloperFindingsDashboard from '../views/DeveloperFindingsDashboard.vue';
import PendingApprovals from '../views/PendingApprovals.vue';
import NotificationSettings from '../views/NotificationSettings.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'Home',
      component: Home,
    },
    {
      path: '/insights',
      name: 'Insights',
      component: Insights,
      props: (route) => ({ 
        defaultTab: route.query.tab || 'overview' 
      })
    },
    {
      path: '/dashboard',
      redirect: (to) => {
        console.warn('Route /dashboard is deprecated. Use /insights?tab=overview instead.');
        return { path: '/insights', query: { ...to.query, tab: 'overview' } };
      }
    },
    {
      path: '/dashboard/app/:id',
      name: 'ApplicationDashboard',
      component: ApplicationDashboard,
    },
    {
      path: '/applications',
      name: 'Applications',
      component: Applications,
    },
    {
      path: '/admin/applications/:id',
      name: 'ApplicationDetail',
      component: ApplicationDetail,
    },
    {
      path: '/dashboard/team/:id',
      name: 'TeamDashboard',
      component: TeamDashboard,
    },
    {
      path: '/tests',
      name: 'TestsOverview',
      component: TestsOverview,
    },
    {
      path: '/tests/batteries',
      name: 'TestBatteries',
      component: TestBatteries,
    },
    {
      path: '/tests/batteries/:id',
      name: 'TestBatteryDetail',
      component: TestBatteryDetail,
    },
    {
      path: '/tests/harnesses',
      name: 'TestHarnesses',
      component: TestHarnesses,
    },
    {
      path: '/tests/harnesses/:id',
      name: 'TestHarnessDetail',
      component: TestHarnessDetail,
    },
    {
      path: '/tests/suites',
      name: 'TestSuites',
      component: TestSuites,
    },
    {
      path: '/tests/suites/new',
      name: 'TestSuiteCreate',
      component: TestSuiteDetail,
    },
    {
      path: '/tests/suites/:id',
      name: 'TestSuiteDetail',
      component: TestSuiteDetail,
    },
    {
      path: '/tests/suites/builder',
      name: 'TestSuiteBuilder',
      component: TestSuiteBuilder,
    },
    {
      path: '/tests/suites/builder/:id',
      name: 'TestSuiteBuilderEdit',
      component: TestSuiteBuilder,
    },
    {
      path: '/tests/library',
      name: 'TestLibrary',
      component: TestLibrary,
    },
    {
      path: '/tests/findings',
      name: 'Findings',
      component: Findings,
    },
    {
      path: '/tests/configurations',
      name: 'TestConfigurations',
      component: TestConfigurations,
    },
    {
      path: '/tests/history',
      name: 'TestHistory',
      component: TestHistory,
    },
    {
      path: '/tests/policy-validation',
      name: 'PolicyValidation',
      component: PolicyValidation,
    },
    {
      path: '/tests/user-simulation',
      name: 'UserSimulation',
      component: UserSimulation,
    },
    // Legacy routes - redirects
    {
      path: '/tests/new',
      redirect: '/tests/suites/new',
    },
    {
      path: '/tests/:id',
      redirect: (to) => ({ path: `/tests/suites/${to.params.id}` }),
    },
    {
      path: '/tests/builder',
      redirect: '/tests/suites/builder',
    },
    {
      path: '/reports',
      redirect: (to) => {
        console.warn('Route /reports is deprecated. Use /insights?tab=reports instead.');
        return { path: '/insights', query: { ...to.query, tab: 'reports' } };
      }
    },
    {
      path: '/policies',
      name: 'Policies',
      component: Policies,
    },
    {
      path: '/policies/:id',
      name: 'PolicyDetail',
      component: PolicyDetail,
    },
    {
      path: '/analytics',
      redirect: (to) => {
        console.warn('Route /analytics is deprecated. Use /insights instead.');
        return { path: '/insights', query: { ...to.query } };
      }
    },
    {
      path: '/violations',
      name: 'Violations',
      component: Violations,
    },
    {
      path: '/findings',
      name: 'UnifiedFindings',
      component: UnifiedFindings,
    },
    {
      path: '/admin/history',
      name: 'History',
      component: History,
    },
    {
      path: '/admin',
      name: 'Admin',
      component: Admin,
    },
    {
      path: '/configuration-validation',
      name: 'ConfigurationValidation',
      component: ConfigurationValidation,
    },
    {
      path: '/distributed-systems',
      redirect: () => {
        console.warn('Route /distributed-systems is deprecated. Use /tests/library?type=distributed-systems instead.');
        return { path: '/tests/library', query: { type: 'distributed-systems' } };
      }
    },
    {
      path: '/pipelines',
      name: 'DataPipelines',
      component: DataPipelines,
    },
    {
      path: '/admin/environments',
      name: 'EphemeralEnvironments',
      component: EphemeralEnvironments,
    },
    {
      path: '/admin/ticketing',
      name: 'TicketingIntegrations',
      component: TicketingIntegrations,
    },
    {
      path: '/admin/sla',
      name: 'SLAManagement',
      component: SLAManagement,
    },
    {
      path: '/api-security',
      redirect: () => {
        console.warn('Route /api-security is deprecated. Use /tests?tab=test-types instead.');
        return { path: '/tests', query: { tab: 'test-types', type: 'api-security' } };
      }
    },
    {
      path: '/settings',
      name: 'Settings',
      component: Settings,
    },
    {
      path: '/admin/integrations',
      name: 'Integrations',
      component: Integrations,
    },
    {
      path: '/admin/ci-cd',
      name: 'CICDIntegration',
      component: CICDIntegration,
    },
    {
      path: '/users',
      redirect: '/tests/user-simulation',
    },
    {
      path: '/resources',
      name: 'Resources',
      component: Resources,
    },
    {
      path: '/contracts',
      name: 'Contracts',
      component: Contracts,
    },
    {
      path: '/datasets',
      name: 'Datasets',
      component: Datasets,
    },
    {
      path: '/compliance',
      name: 'Compliance',
      component: Compliance,
    },
    {
      path: '/how-it-works',
      name: 'HowItWorks',
      component: HowItWorks,
    },
    {
      path: '/repos',
      name: 'Repos',
      component: Repos,
    },
    {
      path: '/access-denied',
      name: 'AccessDenied',
      component: AccessDenied,
    },
    {
      path: '/rls-cls',
      redirect: () => {
        console.warn('Route /rls-cls is deprecated. Use /tests/library?type=rls-cls instead.');
        return { path: '/tests/library', query: { type: 'rls-cls' } };
      }
    },
    {
      path: '/policy-validation',
      redirect: '/tests/policy-validation',
    },
    {
      path: '/identity-providers',
      name: 'IdentityProviders',
      component: IdentityProviders,
    },
    {
      path: '/network-policies',
      redirect: () => {
        console.warn('Route /network-policies is deprecated. Use /tests?tab=test-types instead.');
        return { path: '/tests', query: { tab: 'test-types', type: 'network-policy' } };
      }
    },
    {
      path: '/api-gateway',
      redirect: () => {
        console.warn('Route /api-gateway is deprecated. Use /tests?tab=test-types instead.');
        return { path: '/tests', query: { tab: 'test-types', type: 'api-gateway' } };
      }
    },
    {
      path: '/dlp',
      redirect: () => {
        console.warn('Route /dlp is deprecated. Use /tests?tab=test-types instead.');
        return { path: '/tests', query: { tab: 'test-types', type: 'dlp' } };
      }
    },
    {
      path: '/compliance/nist-800-207',
      name: 'NIST800207',
      component: NIST800207,
    },
    {
      path: '/admin/ci-cd/security-gates',
      name: 'CICDSecurityGates',
      component: CICDSecurityGates,
    },
    {
      path: '/test-configurations',
      redirect: '/tests/configurations',
    },
    {
      path: '/test-history',
      redirect: '/tests/history',
    },
    {
      path: '/compliance-trends',
      name: 'ComplianceTrends',
      component: ComplianceTrends,
    },
    {
      path: '/developer-findings',
      name: 'DeveloperFindingsDashboard',
      component: DeveloperFindingsDashboard,
    },
    {
      path: '/pending-approvals',
      name: 'PendingApprovals',
      component: PendingApprovals,
    },
    {
      path: '/settings/notifications',
      name: 'NotificationSettings',
      component: NotificationSettings,
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: NotFound,
    },
  ],
});

export default router;

