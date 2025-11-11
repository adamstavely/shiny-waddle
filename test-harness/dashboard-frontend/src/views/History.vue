<template>
  <div class="history-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div>
        <h1 class="page-title">History</h1>
        <p class="page-description">View test execution history and audit logs</p>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
      </button>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search history..."
        class="search-input"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterApplication"
        :options="applicationOptions"
        placeholder="All Applications"
        class="filter-dropdown"
      />
      <input
        v-model="filterDateFrom"
        type="date"
        class="filter-date"
        placeholder="From Date"
      />
      <input
        v-model="filterDateTo"
        type="date"
        class="filter-date"
        placeholder="To Date"
      />
    </div>

    <!-- Test Execution History -->
    <div v-if="activeTab === 'executions'" class="tab-content">
      <div class="history-timeline">
        <div
          v-for="execution in filteredExecutions"
          :key="execution.id"
          class="timeline-item"
        >
          <div class="timeline-marker" :class="`status-${execution.status}`">
            <Play v-if="execution.status === 'running'" class="marker-icon" />
            <CheckCircle2 v-else-if="execution.status === 'completed'" class="marker-icon" />
            <X v-else class="marker-icon" />
          </div>
          <div class="timeline-content">
            <div class="timeline-header">
              <h3 class="timeline-title">{{ execution.suiteName }}</h3>
              <span class="timeline-time">{{ formatDateTime(execution.timestamp) }}</span>
            </div>
            <p class="timeline-meta">
              {{ execution.application }} • {{ execution.team }}
            </p>
            <div class="timeline-stats">
              <span class="stat">{{ execution.testCount }} tests</span>
              <span class="stat">{{ execution.passedCount }} passed</span>
              <span class="stat">{{ execution.failedCount }} failed</span>
              <span class="stat score" :class="getScoreClass(execution.score)">
                {{ execution.score }}% compliance
              </span>
            </div>
            <button @click="viewExecutionDetails(execution.id)" class="view-details-btn">
              View Details
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredExecutions.length === 0" class="empty-state">
        <Clock class="empty-icon" />
        <h3>No test executions found</h3>
        <p>Test execution history will appear here</p>
      </div>
    </div>

    <!-- Audit Logs -->
    <div v-if="activeTab === 'audit'" class="tab-content">
      <div class="audit-log">
        <div
          v-for="log in filteredAuditLogs"
          :key="log.id"
          class="audit-entry"
          :class="`log-${log.type}`"
        >
          <div class="audit-icon">
            <component :is="getLogIcon(log.type)" class="icon" />
          </div>
          <div class="audit-content">
            <div class="audit-header">
              <span class="audit-action">{{ log.action }}</span>
              <span class="audit-time">{{ formatDateTime(log.timestamp) }}</span>
            </div>
            <p class="audit-description">{{ log.description }}</p>
            <div class="audit-meta">
              <span class="audit-user">{{ log.user }}</span>
              <span v-if="log.application" class="audit-app">{{ log.application }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="filteredAuditLogs.length === 0" class="empty-state">
        <FileText class="empty-icon" />
        <h3>No audit logs found</h3>
        <p>Audit logs will appear here</p>
      </div>
    </div>

    <!-- Activity Feed -->
    <div v-if="activeTab === 'activity'" class="tab-content">
      <div class="activity-feed">
        <div
          v-for="activity in filteredActivities"
          :key="activity.id"
          class="activity-item"
        >
          <div class="activity-icon" :class="`icon-${activity.type}`">
            <component :is="getActivityIcon(activity.type)" class="icon" />
          </div>
          <div class="activity-content">
            <p class="activity-text">
              <strong>{{ activity.user }}</strong> {{ activity.action }}
            </p>
            <p class="activity-meta">
              {{ activity.details }} • {{ formatRelativeTime(activity.timestamp) }}
            </p>
          </div>
        </div>
      </div>

      <div v-if="filteredActivities.length === 0" class="empty-state">
        <Activity class="empty-icon" />
        <h3>No recent activity</h3>
        <p>Recent activities will appear here</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  History,
  Clock,
  FileText,
  Play,
  CheckCircle2,
  X,
  Edit,
  Shield,
  TestTube,
  FileCheck,
  AlertTriangle,
  Activity
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'History', icon: History }
];

const activeTab = ref<'executions' | 'audit' | 'activity'>('executions');
const searchQuery = ref('');
const filterType = ref('');
const filterApplication = ref('');
const filterDateFrom = ref('');
const filterDateTo = ref('');

const tabs = [
  { id: 'executions', label: 'Test Executions', icon: Clock },
  { id: 'audit', label: 'Audit Logs', icon: FileText },
  { id: 'activity', label: 'Activity Feed', icon: Activity }
];

// Mock test executions
const testExecutions = ref([
  {
    id: '1',
    suiteName: 'Research Tracker API Compliance Tests',
    application: 'research-tracker-api',
    team: 'research-platform',
    status: 'completed',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
    testCount: 24,
    passedCount: 23,
    failedCount: 1,
    score: 95
  },
  {
    id: '2',
    suiteName: 'User Service Compliance Tests',
    application: 'user-service',
    team: 'platform-team',
    status: 'completed',
    timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000),
    testCount: 18,
    passedCount: 13,
    failedCount: 5,
    score: 72
  },
  {
    id: '3',
    suiteName: 'Data Pipeline Compliance Tests',
    application: 'data-pipeline',
    team: 'data-engineering',
    status: 'running',
    timestamp: new Date(Date.now() - 10 * 60 * 1000),
    testCount: 32,
    passedCount: 0,
    failedCount: 0,
    score: 0
  }
]);

// Mock audit logs
const auditLogs = ref([
  {
    id: '1',
    type: 'policy-change',
    action: 'Policy Updated',
    description: 'Default Access Control Policy v1.0.0 was updated to v1.1.0',
    user: 'admin@example.com',
    application: 'research-tracker-api',
    timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000)
  },
  {
    id: '2',
    type: 'test-suite-change',
    action: 'Test Suite Created',
    description: 'New test suite "User Service Compliance Tests" was created',
    user: 'jane.smith@example.com',
    application: 'user-service',
    timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000)
  },
  {
    id: '3',
    type: 'report-generation',
    action: 'Report Generated',
    description: 'Compliance Report - Q4 2024 was generated',
    user: 'admin@example.com',
    application: null,
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000)
  },
  {
    id: '4',
    type: 'violation-resolution',
    action: 'Violation Resolved',
    description: 'Violation "Unauthorized Access to Restricted Resource" was resolved',
    user: 'john.doe@example.com',
    application: 'research-tracker-api',
    timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000)
  }
]);

// Mock activities
const activities = ref([
  {
    id: '1',
    type: 'test-execution',
    user: 'admin@example.com',
    action: 'completed test suite',
    details: 'Research Tracker API Compliance Tests (95% compliance)',
    timestamp: new Date(Date.now() - 30 * 60 * 1000)
  },
  {
    id: '2',
    type: 'policy-update',
    user: 'jane.smith@example.com',
    action: 'updated policy',
    details: 'Default Access Control Policy v1.1.0',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000)
  },
  {
    id: '3',
    type: 'report-generation',
    user: 'admin@example.com',
    action: 'generated report',
    details: 'Compliance Report - Q4 2024',
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000)
  },
  {
    id: '4',
    type: 'violation-resolution',
    user: 'john.doe@example.com',
    action: 'resolved violation',
    details: 'Unauthorized Access to Restricted Resource',
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000)
  }
]);

const applications = computed(() => {
  const execApps = testExecutions.value.map(e => e.application);
  const auditApps = auditLogs.value.filter(l => l.application).map(l => l.application!);
  return [...new Set([...execApps, ...auditApps])];
});

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'Test Execution', value: 'test-execution' },
  { label: 'Policy Change', value: 'policy-change' },
  { label: 'Test Suite Change', value: 'test-suite-change' },
  { label: 'Report Generation', value: 'report-generation' },
  { label: 'Violation Resolution', value: 'violation-resolution' }
]);

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app, value: app }))
  ];
});

const filteredExecutions = computed(() => {
  return testExecutions.value.filter(execution => {
    const matchesSearch = execution.suiteName.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesApp = !filterApplication.value || execution.application === filterApplication.value;
    const matchesDate = (!filterDateFrom.value || new Date(execution.timestamp) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(execution.timestamp) <= new Date(filterDateTo.value));
    return matchesSearch && matchesApp && matchesDate;
  });
});

const filteredAuditLogs = computed(() => {
  return auditLogs.value.filter(log => {
    const matchesSearch = log.action.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                        log.description.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || log.type === filterType.value;
    const matchesApp = !filterApplication.value || log.application === filterApplication.value;
    const matchesDate = (!filterDateFrom.value || new Date(log.timestamp) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(log.timestamp) <= new Date(filterDateTo.value));
    return matchesSearch && matchesType && matchesApp && matchesDate;
  });
});

const filteredActivities = computed(() => {
  return activities.value.filter(activity => {
    const matchesSearch = activity.action.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         activity.details.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || activity.type === filterType.value;
    return matchesSearch && matchesType;
  });
});

const viewExecutionDetails = (id: string) => {
  console.log('View execution details:', id);
};

const getLogIcon = (type: string) => {
  const icons: Record<string, any> = {
    'policy-change': Edit,
    'test-suite-change': TestTube,
    'report-generation': FileCheck,
    'violation-resolution': AlertTriangle
  };
  return icons[type] || FileText;
};

const getActivityIcon = (type: string) => {
  const icons: Record<string, any> = {
    'test-execution': Play,
    'policy-update': Shield,
    'report-generation': FileText,
    'violation-resolution': AlertTriangle
  };
  return icons[type] || Activity;
};

const formatDateTime = (date: Date): string => {
  return date.toLocaleString();
};

const formatRelativeTime = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};
</script>

<style scoped>
.history-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
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

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-date {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown,
.filter-date {
  min-width: 150px;
}

.search-input:focus,
.filter-date:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.tab-content {
  min-height: 400px;
}

.history-timeline {
  position: relative;
  padding-left: 40px;
}

.history-timeline::before {
  content: '';
  position: absolute;
  left: 19px;
  top: 0;
  bottom: 0;
  width: 2px;
  background: rgba(79, 172, 254, 0.2);
}

.timeline-item {
  position: relative;
  margin-bottom: 32px;
}

.timeline-marker {
  position: absolute;
  left: -32px;
  top: 0;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 3px solid;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
}

.timeline-marker.status-completed {
  border-color: #22c55e;
  color: #22c55e;
}

.timeline-marker.status-running {
  border-color: #4facfe;
  color: #4facfe;
  animation: pulse 2s infinite;
}

.timeline-marker.status-failed {
  border-color: #fc8181;
  color: #fc8181;
}

.marker-icon {
  width: 20px;
  height: 20px;
}

@keyframes pulse {
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
}

.timeline-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.timeline-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.timeline-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.timeline-time {
  font-size: 0.875rem;
  color: #718096;
}

.timeline-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 12px;
}

.timeline-stats {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.timeline-stats .stat {
  font-size: 0.875rem;
  color: #a0aec0;
}

.timeline-stats .stat.score {
  font-weight: 600;
}

.score-high {
  color: #22c55e;
}

.score-medium {
  color: #fbbf24;
}

.score-low {
  color: #fc8181;
}

.view-details-btn {
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.view-details-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.audit-log {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.audit-entry {
  display: flex;
  gap: 16px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.audit-icon {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.audit-icon .icon {
  width: 20px;
  height: 20px;
}

.log-policy-change .audit-icon {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.log-test-suite-change .audit-icon {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.log-report-generation .audit-icon {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.log-violation-resolution .audit-icon {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.audit-content {
  flex: 1;
}

.audit-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.audit-action {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
}

.audit-time {
  font-size: 0.875rem;
  color: #718096;
}

.audit-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 8px;
  line-height: 1.5;
}

.audit-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #718096;
}

.activity-feed {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.activity-item {
  display: flex;
  gap: 16px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.activity-icon {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.activity-icon .icon {
  width: 20px;
  height: 20px;
}

.activity-content {
  flex: 1;
}

.activity-text {
  font-size: 0.9rem;
  color: #ffffff;
  margin-bottom: 4px;
  line-height: 1.5;
}

.activity-text strong {
  color: #4facfe;
}

.activity-meta {
  font-size: 0.875rem;
  color: #718096;
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
  color: #4facfe;
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
