import { createRouter, createWebHistory } from 'vue-router';
import Home from '../views/Home.vue';
import Dashboard from '../views/Dashboard.vue';
import ApplicationDashboard from '../views/ApplicationDashboard.vue';
import TeamDashboard from '../views/TeamDashboard.vue';
import Tests from '../views/Tests.vue';
import TestSuiteBuilder from '../views/TestSuiteBuilder.vue';
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
      path: '/dashboard/team/:id',
      name: 'TeamDashboard',
      component: TeamDashboard,
    },
    {
      path: '/tests',
      name: 'Tests',
      component: Tests,
    },
    {
      path: '/tests/builder',
      name: 'TestSuiteBuilder',
      component: TestSuiteBuilder,
    },
    {
      path: '/tests/builder/:id',
      name: 'TestSuiteBuilderEdit',
      component: TestSuiteBuilder,
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
      name: 'DistributedSystems',
      component: DistributedSystems,
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
      name: 'ApiSecurity',
      component: ApiSecurity,
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
      name: 'UserSimulation',
      component: UserSimulation,
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
      path: '/:pathMatch(.*)*',
      name: 'NotFound',
      component: NotFound,
    },
  ],
});

export default router;

