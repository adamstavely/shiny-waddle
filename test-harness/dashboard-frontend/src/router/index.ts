import { createRouter, createWebHistory } from 'vue-router';
import Home from '../views/Home.vue';
import Dashboard from '../views/Dashboard.vue';
import ApplicationDashboard from '../views/ApplicationDashboard.vue';
import ApplicationDetail from '../views/ApplicationDetail.vue';
import Applications from '../views/Applications.vue';
import TeamDashboard from '../views/TeamDashboard.vue';
import TestsOverview from '../views/TestsOverview.vue';
import AccessControlOverview from '../views/AccessControlOverview.vue';
import PlatformConfigOverview from '../views/PlatformConfigOverview.vue';
import TestBatteries from '../views/TestBatteries.vue';
import TestHarnesses from '../views/TestHarnesses.vue';
import TestSuites from '../views/TestSuites.vue';
import TestLibrary from '../views/TestLibrary.vue';
import Findings from '../views/Findings.vue';
import TestSuiteBuilder from '../views/TestSuiteBuilder.vue';
import TestSuiteDetail from '../views/TestSuiteDetail.vue';
import TestBatteryDetail from '../views/TestBatteryDetail.vue';
import TestBatteryCreate from '../views/TestBatteryCreate.vue';
import TestHarnessDetail from '../views/TestHarnessDetail.vue';
import TestHarnessCreate from '../views/TestHarnessCreate.vue';
import Reports from '../views/Reports.vue';
import RunsAndReports from '../views/RunsAndReports.vue';
import Policies from '../views/Policies.vue';
import PolicyDetail from '../views/PolicyDetail.vue';
import Insights from '../views/insights/Insights.vue';
import Violations from '../views/Violations.vue';
import History from '../views/History.vue';
import Admin from '../views/Admin.vue';
import ConfigurationValidation from '../views/ConfigurationValidation.vue';
import DataPipelines from '../views/DataPipelines.vue';
import EphemeralEnvironments from '../views/EphemeralEnvironments.vue';
import Settings from '../views/Settings.vue';
import Integrations from '../views/Integrations.vue';
import CICDIntegration from '../views/CICDIntegration.vue';
import Resources from '../views/Resources.vue';
import TicketingIntegrations from '../views/TicketingIntegrations.vue';
import SLAManagement from '../views/SLAManagement.vue';
import Compliance from '../views/Compliance.vue';
import UnifiedFindings from '../views/UnifiedFindings.vue';
import HowItWorks from '../views/HowItWorks.vue';
import Repos from '../views/Repos.vue';
import NotFound from '../views/NotFound.vue';
import AccessDenied from '../views/AccessDenied.vue';
import PolicyValidation from '../views/PolicyValidation.vue';
import IdentityProviders from '../views/IdentityProviders.vue';
import NIST800207 from '../views/NIST800207.vue';
import CICDSecurityGates from '../views/CICDSecurityGates.vue';
import TestHistory from '../views/TestHistory.vue';
import ComplianceTrends from '../views/ComplianceTrends.vue';
import DeveloperFindingsDashboard from '../views/DeveloperFindingsDashboard.vue';
import PendingApprovals from '../views/PendingApprovals.vue';
import NotificationSettings from '../views/NotificationSettings.vue';
import IAMIntegrations from '../views/IAMIntegrations.vue';
import EnvironmentConfigTesting from '../views/EnvironmentConfigTesting.vue';
import SalesforceExperienceCloud from '../views/SalesforceExperienceCloud.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'Home',
      component: Home,
    },
    {
      path: '/dashboard',
      name: 'Dashboard',
      component: Dashboard,
    },
    {
      path: '/applications',
      name: 'Applications',
      component: Applications,
    },
    {
      path: '/applications/:id',
      name: 'ApplicationDetail',
      component: ApplicationDetail,
    },
    {
      path: '/admin/applications/:id',
      name: 'AdminApplicationDetail',
      component: ApplicationDetail,
    },
    {
      path: '/insights',
      name: 'Insights',
      component: () => import('../views/insights/InsightsOverview.vue'),
    },
    {
      path: '/insights/overview',
      name: 'InsightsOverviewContent',
      component: () => import('../views/insights/InsightsOverviewContent.vue'),
    },
    {
      path: '/insights/analytics',
      name: 'InsightsAnalytics',
      component: () => import('../views/insights/InsightsAnalytics.vue'),
    },
    {
      path: '/insights/predictions',
      name: 'InsightsPredictions',
      component: () => import('../views/insights/InsightsPredictions.vue'),
    },
    {
      path: '/insights/runs',
      name: 'InsightsRuns',
      component: () => import('../views/insights/InsightsRuns.vue'),
    },
    {
      path: '/insights/reports',
      name: 'InsightsReports',
      component: () => import('../views/insights/InsightsReports.vue'),
    },
    {
      path: '/insights/trends',
      name: 'InsightsTrends',
      component: () => import('../views/insights/InsightsTrends.vue'),
    },
    {
      path: '/dashboard/app/:id',
      name: 'ApplicationDashboard',
      component: ApplicationDashboard,
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
      path: '/tests/individual',
      name: 'Tests',
      component: () => import('../views/Tests.vue'),
    },
    {
      path: '/tests/individual/new',
      name: 'TestCreate',
      component: () => import('../views/TestCreate.vue'),
    },
    {
      path: '/tests/individual/:id/edit',
      name: 'TestEdit',
      component: () => import('../views/TestCreate.vue'),
    },
    {
      path: '/tests/batteries',
      name: 'TestBatteries',
      component: TestBatteries,
    },
    {
      path: '/tests/batteries/new',
      name: 'TestBatteryCreate',
      component: TestBatteryCreate,
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
      path: '/tests/harnesses/new',
      name: 'TestHarnessCreate',
      component: TestHarnessCreate,
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
      path: '/tests/test/:id',
      name: 'TestDetail',
      component: () => import('../views/TestDetail.vue'),
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
      path: '/access-control',
      name: 'AccessControlOverview',
      component: AccessControlOverview,
    },
    {
      path: '/platform-config',
      name: 'PlatformConfigOverview',
      component: PlatformConfigOverview,
    },
    {
      path: '/runs',
      name: 'RunsAndReports',
      redirect: '/insights/runs',
    },
    {
      path: '/policies',
      name: 'Policies',
      component: () => import('../views/policies/PoliciesOverview.vue'),
    },
    {
      path: '/policies/access-control',
      name: 'AccessControlPolicies',
      component: () => import('../views/policies/AccessControlPolicies.vue'),
    },
    {
      path: '/policies/data-classification',
      name: 'DataClassificationPolicies',
      component: () => import('../views/policies/DataClassificationPolicies.vue'),
    },
    {
      path: '/policies/platform-config',
      name: 'PlatformConfigPolicies',
      component: () => import('../views/policies/PlatformConfigPolicies.vue'),
    },
    {
      path: '/policies/exceptions',
      name: 'ExceptionsPolicies',
      component: () => import('../views/policies/ExceptionsPolicies.vue'),
    },
    {
      path: '/policies/standards-mapping',
      name: 'StandardsMappingPolicies',
      component: () => import('../views/policies/StandardsMappingPolicies.vue'),
    },
    {
      path: '/policies/data-contracts',
      name: 'DataContractsPolicies',
      component: () => import('../views/policies/DataContractsPolicies.vue'),
    },
    {
      path: '/policies/salesforce',
      name: 'SalesforceBaselinesPolicies',
      component: () => import('../views/policies/SalesforceBaselinesPolicies.vue'),
    },
    {
      path: '/policies/elastic',
      name: 'ElasticBaselinesPolicies',
      component: () => import('../views/policies/ElasticBaselinesPolicies.vue'),
    },
    {
      path: '/policies/idp-platform',
      name: 'IDPPlatformPolicies',
      component: () => import('../views/policies/IDPPlatformPolicies.vue'),
    },
    {
      path: '/policies/:id',
      name: 'PolicyDetail',
      component: PolicyDetail,
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
      path: '/admin/integrations/iam',
      name: 'IAMIntegrations',
      component: IAMIntegrations,
    },
    {
      path: '/admin/ci-cd',
      name: 'CICDIntegration',
      component: CICDIntegration,
    },
    {
      path: '/resources',
      name: 'Resources',
      component: Resources,
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
      path: '/identity-providers',
      name: 'IdentityProviders',
      component: IdentityProviders,
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
      path: '/environment-config-testing',
      name: 'EnvironmentConfigTesting',
      component: EnvironmentConfigTesting,
    },
    {
      path: '/salesforce-experience-cloud',
      name: 'SalesforceExperienceCloud',
      component: SalesforceExperienceCloud,
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: NotFound,
    },
  ],
});

export default router;

