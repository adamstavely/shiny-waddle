<template>
  <div class="violations-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Violations</h1>
          <p class="page-description">View and manage access control violations</p>
        </div>
        <div class="header-stats">
          <div class="stat-card critical">
            <span class="stat-label">Critical</span>
            <span class="stat-value">{{ criticalCount }}</span>
          </div>
          <div class="stat-card open">
            <span class="stat-label">Open</span>
            <span class="stat-value">{{ openCount }}</span>
          </div>
          <div class="stat-card resolved">
            <span class="stat-label">Resolved</span>
            <span class="stat-value">{{ resolvedCount }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search violations..."
        class="search-input"
      />
      <Dropdown
        v-model="filterSeverity"
        :options="severityOptions"
        placeholder="All Severities"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterApplication"
        :options="applicationOptions"
        placeholder="All Applications"
        class="filter-dropdown"
      />
    </div>

    <!-- Violations List -->
    <div class="violations-list">
      <div
        v-for="violation in filteredViolations"
        :key="violation.id"
        class="violation-card"
        :class="`severity-${violation.severity}`"
        @click="viewViolation(violation.id)"
      >
        <div class="violation-header">
          <div class="violation-title-row">
            <div class="violation-title-group">
              <AlertTriangle class="violation-icon" :class="`icon-${violation.severity}`" />
              <h3 class="violation-title">{{ violation.title }}</h3>
            </div>
            <div class="violation-badges">
              <span class="severity-badge" :class="`badge-${violation.severity}`">
                {{ violation.severity }}
              </span>
              <span class="status-badge" :class="`status-${violation.status}`">
                {{ violation.status }}
              </span>
            </div>
          </div>
          <p class="violation-meta">
            {{ violation.application }} • {{ violation.team }} • {{ formatDate(violation.detectedAt) }}
          </p>
        </div>

        <p class="violation-description">{{ violation.description }}</p>

        <div class="violation-details">
          <div class="detail-item">
            <span class="detail-label">Type:</span>
            <span class="detail-value">{{ violation.type }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Policy:</span>
            <span class="detail-value">{{ violation.policyName }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Resource:</span>
            <span class="detail-value">{{ violation.resource }}</span>
          </div>
        </div>

        <div class="violation-actions">
          <button @click.stop="assignViolation(violation.id)" class="action-btn assign-btn">
            <User class="action-icon" />
            Assign
          </button>
          <button @click.stop="resolveViolation(violation.id)" class="action-btn resolve-btn">
            <CheckCircle2 class="action-icon" />
            Resolve
          </button>
          <button @click.stop="ignoreViolation(violation.id)" class="action-btn ignore-btn">
            <X class="action-icon" />
            Ignore
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredViolations.length === 0" class="empty-state">
      <CheckCircle2 class="empty-icon" />
      <h3>No violations found</h3>
      <p>All access control policies are being followed</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  AlertTriangle,
  CheckCircle2,
  X,
  User
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Violations', icon: AlertTriangle }
];

const searchQuery = ref('');
const filterSeverity = ref('');
const filterType = ref('');
const filterStatus = ref('');
const filterApplication = ref('');

// Mock violations data
const violations = ref([
  {
    id: '1',
    title: 'Unauthorized Access to Restricted Resource',
    description: 'User with viewer role attempted to access restricted PII data without proper clearance',
    type: 'access-control',
    severity: 'critical',
    status: 'open',
    application: 'research-tracker-api',
    team: 'research-platform',
    policyName: 'Default Access Control Policy',
    resource: 'pii-data',
    detectedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    assignedTo: null
  },
  {
    id: '2',
    title: 'Raw Email Export Detected',
    description: 'Query attempted to export raw email addresses, violating contract requirement',
    type: 'contract',
    severity: 'high',
    status: 'in-progress',
    application: 'user-service',
    team: 'platform-team',
    policyName: 'No Raw Email Export',
    resource: 'user-data',
    detectedAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
    assignedTo: 'john.doe@example.com'
  },
  {
    id: '3',
    title: 'Disallowed Join Operation',
    description: 'Viewer role attempted to join users table, which is disallowed by policy',
    type: 'data-behavior',
    severity: 'medium',
    status: 'open',
    application: 'research-tracker-api',
    team: 'research-platform',
    policyName: 'Data Behavior Policy',
    resource: 'reports',
    detectedAt: new Date(Date.now() - 8 * 60 * 60 * 1000),
    assignedTo: null
  },
  {
    id: '4',
    title: 'Privacy Threshold Violation',
    description: 'Dataset failed k-anonymity threshold (k=10), only achieved k=7',
    type: 'dataset-health',
    severity: 'high',
    status: 'resolved',
    application: 'data-pipeline',
    team: 'data-engineering',
    policyName: 'Privacy Threshold Policy',
    resource: 'masked-users',
    detectedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
    assignedTo: 'jane.smith@example.com'
  },
  {
    id: '5',
    title: 'Missing Required Filter',
    description: 'Query executed without required workspace_id filter for viewer role',
    type: 'data-behavior',
    severity: 'medium',
    status: 'ignored',
    application: 'research-tracker-api',
    team: 'research-platform',
    policyName: 'Data Behavior Policy',
    resource: 'reports',
    detectedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
    assignedTo: null
  }
]);

const applications = computed(() => {
  return [...new Set(violations.value.map(v => v.application))];
});

const severityOptions = computed(() => [
  { label: 'All Severities', value: '' },
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' }
]);

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'Access Control', value: 'access-control' },
  { label: 'Data Behavior', value: 'data-behavior' },
  { label: 'Contract', value: 'contract' },
  { label: 'Dataset Health', value: 'dataset-health' }
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Open', value: 'open' },
  { label: 'In Progress', value: 'in-progress' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'Ignored', value: 'ignored' }
]);

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app, value: app }))
  ];
});

const criticalCount = computed(() => {
  return violations.value.filter(v => v.severity === 'critical' && v.status !== 'resolved').length;
});

const openCount = computed(() => {
  return violations.value.filter(v => v.status === 'open').length;
});

const resolvedCount = computed(() => {
  return violations.value.filter(v => v.status === 'resolved').length;
});

const filteredViolations = computed(() => {
  return violations.value.filter(violation => {
    const matchesSearch = violation.title.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         violation.description.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesSeverity = !filterSeverity.value || violation.severity === filterSeverity.value;
    const matchesType = !filterType.value || violation.type === filterType.value;
    const matchesStatus = !filterStatus.value || violation.status === filterStatus.value;
    const matchesApp = !filterApplication.value || violation.application === filterApplication.value;
    return matchesSearch && matchesSeverity && matchesType && matchesStatus && matchesApp;
  });
});

const viewViolation = (id: string) => {
  console.log('View violation:', id);
  // Navigate to violation detail page
};

const assignViolation = (id: string) => {
  const violation = violations.value.find(v => v.id === id);
  if (violation) {
    const assignee = prompt('Enter assignee email:');
    if (assignee) {
      violation.assignedTo = assignee;
      violation.status = 'in-progress';
    }
  }
};

const resolveViolation = (id: string) => {
  if (confirm('Mark this violation as resolved?')) {
    const violation = violations.value.find(v => v.id === id);
    if (violation) {
      violation.status = 'resolved';
    }
  }
};

const ignoreViolation = (id: string) => {
  if (confirm('Ignore this violation? It will be marked as ignored.')) {
    const violation = violations.value.find(v => v.id === id);
    if (violation) {
      violation.status = 'ignored';
    }
  }
};

const formatDate = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};
</script>

<style scoped>
.violations-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.header-stats {
  display: flex;
  gap: 16px;
}

.stat-card {
  padding: 16px 24px;
  border-radius: 12px;
  border: 1px solid;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 120px;
}

.stat-card.critical {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.3);
}

.stat-card.open {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.3);
}

.stat-card.resolved {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.3);
}

.stat-label {
  font-size: 0.75rem;
  font-weight: 500;
  color: #a0aec0;
  text-transform: uppercase;
}

.stat-card.critical .stat-label {
  color: #fc8181;
}

.stat-card.open .stat-label {
  color: #fbbf24;
}

.stat-card.resolved .stat-label {
  color: #22c55e;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #ffffff;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.violations-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.violation-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-left: 4px solid;
  border-radius: 12px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.violation-card.severity-critical {
  border-left-color: #fc8181;
  background: linear-gradient(135deg, rgba(252, 129, 129, 0.05) 0%, #1a1f2e 100%);
}

.violation-card.severity-high {
  border-left-color: #fbbf24;
}

.violation-card.severity-medium {
  border-left-color: #4facfe;
}

.violation-card.severity-low {
  border-left-color: #718096;
}

.violation-card:hover {
  transform: translateX(4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.violation-header {
  margin-bottom: 16px;
}

.violation-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
  gap: 16px;
}

.violation-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.violation-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
}

.icon-critical {
  color: #fc8181;
}

.icon-high {
  color: #fbbf24;
}

.icon-medium {
  color: #4facfe;
}

.icon-low {
  color: #718096;
}

.violation-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.violation-badges {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.severity-badge,
.status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.badge-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.badge-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.badge-medium {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.badge-low {
  background: rgba(113, 128, 150, 0.2);
  color: #718096;
}

.status-open {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-in-progress {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-resolved {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-ignored {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.violation-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.violation-description {
  font-size: 0.9rem;
  color: #a0aec0;
  line-height: 1.5;
  margin-bottom: 16px;
}

.violation-details {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-item {
  display: flex;
  gap: 8px;
  font-size: 0.875rem;
}

.detail-label {
  color: #718096;
  font-weight: 500;
}

.detail-value {
  color: #ffffff;
}

.violation-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.assign-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.resolve-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.ignore-btn:hover {
  background: rgba(156, 163, 175, 0.1);
  border-color: rgba(156, 163, 175, 0.5);
  color: #9ca3af;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #22c55e;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
}
</style>
