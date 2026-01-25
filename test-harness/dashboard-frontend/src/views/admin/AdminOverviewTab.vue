<template>
  <div class="admin-overview-tab">
    <div class="overview-grid">
      <!-- Statistics Cards -->
      <div class="stat-card">
        <div class="stat-header">
          <Server class="stat-icon" />
          <h3 class="stat-title">Applications</h3>
        </div>
        <div class="stat-value">{{ applicationsCount }}</div>
        <div class="stat-label">Registered</div>
        <div class="stat-detail">
          <span class="stat-detail-item">
            <span class="detail-value">{{ activeApplications }}</span>
            <span class="detail-label">Active</span>
          </span>
          <span class="stat-detail-item">
            <span class="detail-value">{{ inactiveApplications }}</span>
            <span class="detail-label">Inactive</span>
          </span>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-header">
          <TestTube class="stat-icon" />
          <h3 class="stat-title">Tests</h3>
        </div>
        <div class="stat-value">{{ totalTests }}</div>
        <div class="stat-label">Total Executed</div>
        <div class="stat-detail">
          <span class="stat-detail-item">
            <span class="detail-value">{{ passedTests }}</span>
            <span class="detail-label">Passed</span>
          </span>
          <span class="stat-detail-item">
            <span class="detail-value">{{ failedTests }}</span>
            <span class="detail-label">Failed</span>
          </span>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-header">
          <Shield class="stat-icon" />
          <h3 class="stat-title">Policies</h3>
        </div>
        <div class="stat-value">{{ totalPolicies }}</div>
        <div class="stat-label">Configured</div>
        <div class="stat-detail">
          <span class="stat-detail-item">
            <span class="detail-value">{{ activePolicies }}</span>
            <span class="detail-label">Active</span>
          </span>
          <span class="stat-detail-item">
            <span class="detail-value">{{ rbacPolicies }}</span>
            <span class="detail-label">RBAC</span>
          </span>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-header">
          <Users class="stat-icon" />
          <h3 class="stat-title">Teams</h3>
        </div>
        <div class="stat-value">{{ totalTeams }}</div>
        <div class="stat-label">Monitored</div>
        <div class="stat-detail">
          <span class="stat-detail-item">
            <span class="detail-value">{{ avgCompliance }}</span>
            <span class="detail-label">Avg Compliance</span>
          </span>
        </div>
      </div>
    </div>

    <!-- System Health -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">
          <Activity class="title-icon" />
          System Health
        </h2>
      </div>
      <div class="health-grid">
        <div class="health-item">
          <div class="health-label">API Status</div>
          <div class="health-value status-healthy">Healthy</div>
          <div class="health-detail">Response time: 45ms</div>
        </div>
        <div class="health-item">
          <div class="health-label">Database</div>
          <div class="health-value status-healthy">Connected</div>
          <div class="health-detail">Last sync: 2 min ago</div>
        </div>
        <div class="health-item">
          <div class="health-label">Test Runner</div>
          <div class="health-value status-healthy">Running</div>
          <div class="health-detail">Queue: 3 pending</div>
        </div>
        <div class="health-item">
          <div class="health-label">Storage</div>
          <div class="health-value status-warning">75% Used</div>
          <div class="health-detail">2.1 GB / 2.8 GB</div>
        </div>
      </div>
    </div>

    <!-- Recent Activity -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">
          <Clock class="title-icon" />
          Recent Activity
        </h2>
      </div>
      <div class="activity-list">
        <div
          v-for="(activity, index) in recentActivity"
          :key="index"
          class="activity-item"
        >
          <div class="activity-icon" :class="`activity-${activity.type}`">
            <component :is="activity.icon" class="icon" />
          </div>
          <div class="activity-content">
            <div class="activity-title">{{ activity.title }}</div>
            <div class="activity-meta">
              {{ activity.user }} • {{ formatTimeAgo(activity.timestamp) }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Quick Actions -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">Quick Actions</h2>
      </div>
      <div class="actions-grid">
        <button @click="$emit('register-app')" class="quick-action-btn">
          <Plus class="action-icon" />
          <span>Register Application</span>
        </button>
        <button @click="$emit('run-system-test')" class="quick-action-btn">
          <TestTube class="action-icon" />
          <span>Run System Test</span>
        </button>
        <button @click="$emit('view-logs')" class="quick-action-btn">
          <Activity class="action-icon" />
          <span>View System Logs</span>
        </button>
        <button @click="$emit('export-config')" class="quick-action-btn">
          <Settings class="action-icon" />
          <span>Export Configuration</span>
        </button>
      </div>
    </div>

    <!-- Integration Management -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">Integrations & CI/CD</h2>
        <p class="section-description">Manage external integrations and CI/CD pipeline configurations</p>
      </div>
      <div class="integration-cards-grid">
        <router-link to="/admin/ci-cd" class="integration-card">
          <div class="integration-card-header">
            <GitBranch class="integration-icon" />
            <h3 class="integration-title">CI/CD Integration</h3>
          </div>
          <p class="integration-description">
            Configure and monitor compliance testing in GitHub Actions and Jenkins pipelines
          </p>
          <div class="integration-footer">
            <span class="integration-link">Configure →</span>
          </div>
        </router-link>

        <router-link to="/admin/integrations" class="integration-card">
          <div class="integration-card-header">
            <Plug class="integration-icon" />
            <h3 class="integration-title">External Integrations</h3>
          </div>
          <p class="integration-description">
            Connect and manage SAST, DAST, DBT, and Great Expectations integrations
          </p>
          <div class="integration-footer">
            <span class="integration-link">Manage →</span>
          </div>
        </router-link>
      </div>
    </div>

    <!-- History & Audit -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">History & Audit</h2>
        <p class="section-description">View test execution history, audit logs, and activity feed</p>
      </div>
      <div class="integration-cards-grid">
        <router-link to="/admin/history" class="integration-card">
          <div class="integration-card-header">
            <Clock class="integration-icon" />
            <h3 class="integration-title">History</h3>
          </div>
          <p class="integration-description">
            View test execution history, audit logs, and system activity feed with comprehensive filtering
          </p>
          <div class="integration-footer">
            <span class="integration-link">View History →</span>
          </div>
        </router-link>
      </div>
    </div>

    <!-- Environments -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">Environments</h2>
        <p class="section-description">Manage ephemeral environments for testing and validation</p>
      </div>
      <div class="integration-cards-grid">
        <router-link to="/admin/environments" class="integration-card">
          <div class="integration-card-header">
            <Cloud class="integration-icon" />
            <h3 class="integration-title">Ephemeral Environments</h3>
          </div>
          <p class="integration-description">
            Create, monitor, and manage ephemeral environments for PR testing and validation
          </p>
          <div class="integration-footer">
            <span class="integration-link">Manage →</span>
          </div>
        </router-link>
      </div>
    </div>

    <!-- Remediation & Workflows -->
    <div class="section-card">
      <div class="section-header-inline">
        <h2 class="section-title">Remediation & Workflows</h2>
        <p class="section-description">Configure ticketing integrations, SLA policies, and automated remediation</p>
      </div>
      <div class="integration-cards-grid">
        <router-link to="/admin/ticketing" class="integration-card">
          <div class="integration-card-header">
            <Ticket class="integration-icon" />
            <h3 class="integration-title">Ticketing Integrations</h3>
          </div>
          <p class="integration-description">
            Connect Jira, ServiceNow, or GitHub to automatically create tickets for violations
          </p>
          <div class="integration-footer">
            <span class="integration-link">Configure →</span>
          </div>
        </router-link>

      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import {
  Server,
  TestTube,
  Shield,
  Users,
  Activity,
  Clock,
  Plus,
  Settings,
  GitBranch,
  Plug,
  Cloud,
  Ticket
} from 'lucide-vue-next';

interface Props {
  applicationsCount: number;
  activeApplications: number;
  inactiveApplications: number;
  totalTests: number;
  passedTests: number;
  failedTests: number;
  totalPolicies: number;
  activePolicies: number;
  rbacPolicies: number;
  totalTeams: number;
  avgCompliance: string;
}

const props = withDefaults(defineProps<Props>(), {
  applicationsCount: 0,
  activeApplications: 0,
  inactiveApplications: 0,
  totalTests: 1247,
  passedTests: 1189,
  failedTests: 58,
  totalPolicies: 12,
  activePolicies: 10,
  rbacPolicies: 7,
  totalTeams: 5,
  avgCompliance: '87.5%'
});

defineEmits<{
  'register-app': [];
  'run-system-test': [];
  'view-logs': [];
  'export-config': [];
}>();

const recentActivity = ref([
  {
    type: 'test',
    icon: TestTube,
    title: 'Test suite executed for Research Tracker API',
    user: 'system',
    timestamp: new Date(Date.now() - 5 * 60 * 1000)
  },
  {
    type: 'register',
    icon: Server,
    title: 'New application registered: User Service',
    user: 'admin@example.com',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000)
  },
  {
    type: 'policy',
    icon: Shield,
    title: 'Policy updated: Default Access Control Policy',
    user: 'admin@example.com',
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000)
  },
  {
    type: 'violation',
    icon: Activity,
    title: 'Violation detected: Unauthorized access attempt',
    user: 'system',
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000)
  }
]);

const formatTimeAgo = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
};
</script>

<style scoped>
/* Styles will be inherited from Admin.vue or can be scoped here */
.admin-overview-tab {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-lg);
}

.stat-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.stat-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.stat-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.stat-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.stat-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.stat-detail {
  display: flex;
  gap: var(--spacing-lg);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.stat-detail-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.detail-value {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.detail-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.section-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.section-header-inline {
  margin-bottom: var(--spacing-lg);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.section-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.health-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.health-item {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
}

.health-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.health-value {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  margin-bottom: var(--spacing-xs);
}

.status-healthy {
  color: var(--color-success);
}

.status-warning {
  color: var(--color-warning);
}

.health-detail {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.activity-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.activity-item {
  display: flex;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
}

.activity-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--border-radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.activity-content {
  flex: 1;
}

.activity-title {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.activity-meta {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.quick-action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  cursor: pointer;
  transition: var(--transition-all);
}

.quick-action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: var(--border-color-primary-active);
  color: var(--color-primary);
}

.action-icon {
  width: 20px;
  height: 20px;
}

.integration-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--spacing-lg);
}

.integration-card {
  display: flex;
  flex-direction: column;
  padding: var(--spacing-lg);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  text-decoration: none;
  color: inherit;
  transition: var(--transition-all);
}

.integration-card:hover {
  border-color: var(--border-color-primary-active);
  background: rgba(79, 172, 254, 0.05);
}

.integration-card-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.integration-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.integration-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.integration-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
  flex: 1;
}

.integration-footer {
  margin-top: auto;
}

.integration-link {
  font-size: var(--font-size-sm);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
}
</style>
