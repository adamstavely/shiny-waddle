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
import Analytics from '../views/Analytics.vue';
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
      name: 'Reports',
      component: Reports,
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
      name: 'Analytics',
      component: Analytics,
    },
    {
      path: '/violations',
      name: 'Violations',
      component: Violations,
    },
    {
      path: '/history',
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
      path: '/environments',
      name: 'EphemeralEnvironments',
      component: EphemeralEnvironments,
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
      path: '/integrations',
      name: 'Integrations',
      component: Integrations,
    },
    {
      path: '/ci-cd',
      name: 'CICDIntegration',
      component: CICDIntegration,
    },
  ],
});

export default router;

