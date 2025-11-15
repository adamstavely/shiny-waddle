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
      <Dropdown
        v-model="filterTeam"
        :options="teamOptions"
        placeholder="All Teams"
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

    <!-- Loading State -->
    <div v-if="loading" class="loading-state">
      <p>Loading history...</p>
    </div>

    <!-- Test Execution History -->
    <div v-else-if="activeTab === 'executions'" class="tab-content">
      <div class="history-timeline">
        <div
          v-for="execution in filteredExecutions"
          :key="execution.id"
          class="timeline-item"
          :class="{ 'selected-for-compare': selectedForCompare.includes(execution.id) }"
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
              <span v-if="execution.application">{{ execution.application }}</span>
              <span v-if="execution.application && execution.team"> • </span>
              <span v-if="execution.team">{{ execution.team }}</span>
            </p>
            <div class="timeline-stats">
              <span class="stat">{{ execution.testCount }} tests</span>
              <span class="stat">{{ execution.passedCount }} passed</span>
              <span class="stat">{{ execution.failedCount }} failed</span>
              <span class="stat score" :class="getScoreClass(execution.score)">
                {{ execution.score }}% compliance
              </span>
              <span v-if="execution.duration" class="stat">
                {{ formatDuration(execution.duration) }}
              </span>
            </div>
            <div class="timeline-actions">
              <button @click="viewExecutionDetails(execution.id)" class="view-details-btn">
                View Details
              </button>
              <button 
                v-if="selectedForCompare.includes(execution.id)"
                @click="deselectForCompare(execution.id)"
                class="compare-btn selected"
              >
                <X class="btn-icon" />
                Deselect
              </button>
              <button 
                v-else-if="selectedForCompare.length < 2"
                @click="selectForCompare(execution.id)"
                class="compare-btn"
              >
                <GitCompare class="btn-icon" />
                Compare
              </button>
            </div>
          </div>
        </div>
      </div>

      <div v-if="selectedForCompare.length === 2" class="compare-section">
        <button @click="compareExecutions" class="compare-execute-btn">
          <GitCompare class="btn-icon" />
          Compare Selected Executions
        </button>
      </div>

      <div v-if="!loading && filteredExecutions.length === 0" class="empty-state">
        <Clock class="empty-icon" />
        <h3>No test executions found</h3>
        <p>Test execution history will appear here</p>
      </div>
    </div>

    <!-- Audit Logs -->
    <div v-else-if="activeTab === 'audit'" class="tab-content">
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
              <span v-if="log.team" class="audit-team">{{ log.team }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="!loading && filteredAuditLogs.length === 0" class="empty-state">
        <FileText class="empty-icon" />
        <h3>No audit logs found</h3>
        <p>Audit logs will appear here</p>
      </div>
    </div>

    <!-- Activity Feed -->
    <div v-else-if="activeTab === 'activity'" class="tab-content">
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

      <div v-if="!loading && filteredActivities.length === 0" class="empty-state">
        <Activity class="empty-icon" />
        <h3>No recent activity</h3>
        <p>Recent activities will appear here</p>
      </div>
    </div>

    <!-- Execution Details Modal -->
    <ExecutionDetailsModal
      :show="showExecutionModal"
      :execution="selectedExecution"
      @close="closeExecutionModal"
    />

    <!-- Comparison Modal -->
    <ComparisonModal
      :show="showComparisonModal"
      :comparison="comparisonData"
      @close="closeComparisonModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
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
  Activity,
  GitCompare,
  Settings,
  User
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ExecutionDetailsModal from '../components/ExecutionDetailsModal.vue';
import ComparisonModal from '../components/ComparisonModal.vue';
import type {
  TestExecutionEntity,
  AuditLogEntity,
  ActivityEntity,
} from '../types/history';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'History' }
];

const API_BASE_URL = '/api';

const activeTab = ref<'executions' | 'audit' | 'activity'>('executions');
const searchQuery = ref('');
const filterType = ref('');
const filterApplication = ref('');
const filterTeam = ref('');
const filterDateFrom = ref('');
const filterDateTo = ref('');
const loading = ref(true);
const selectedForCompare = ref<string[]>([]);
const showExecutionModal = ref(false);
const showComparisonModal = ref(false);
const selectedExecution = ref<TestExecutionEntity | null>(null);
const comparisonData = ref<any>(null);

const testExecutions = ref<TestExecutionEntity[]>([]);
const auditLogs = ref<AuditLogEntity[]>([]);
const activities = ref<ActivityEntity[]>([]);

const tabs = [
  { id: 'executions', label: 'Test Executions', icon: Clock },
  { id: 'audit', label: 'Audit Logs', icon: FileText },
  { id: 'activity', label: 'Activity Feed', icon: Activity }
];

const applications = computed(() => {
  const execApps = testExecutions.value.map(e => e.application).filter(Boolean);
  const auditApps = auditLogs.value.filter(l => l.application).map(l => l.application!);
  return [...new Set([...execApps, ...auditApps])];
});

const teams = computed(() => {
  const execTeams = testExecutions.value.map(e => e.team).filter(Boolean);
  const auditTeams = auditLogs.value.filter(l => l.team).map(l => l.team!);
  return [...new Set([...execTeams, ...auditTeams])];
});

const typeOptions = computed(() => {
  if (activeTab.value === 'executions') {
    return [
      { label: 'All Statuses', value: '' },
      { label: 'Completed', value: 'completed' },
      { label: 'Running', value: 'running' },
      { label: 'Failed', value: 'failed' },
      { label: 'Cancelled', value: 'cancelled' }
    ];
  } else if (activeTab.value === 'audit') {
    return [
      { label: 'All Types', value: '' },
      { label: 'Policy Change', value: 'policy-change' },
      { label: 'Test Suite Change', value: 'test-suite-change' },
      { label: 'Report Generation', value: 'report-generation' },
      { label: 'Violation Resolution', value: 'violation-resolution' },
      { label: 'User Action', value: 'user-action' },
      { label: 'System Event', value: 'system-event' }
    ];
  } else {
    return [
      { label: 'All Types', value: '' },
      { label: 'Test Execution', value: 'test-execution' },
      { label: 'Policy Update', value: 'policy-update' },
      { label: 'Report Generation', value: 'report-generation' },
      { label: 'Violation Resolution', value: 'violation-resolution' },
      { label: 'Test Suite Created', value: 'test-suite-created' },
      { label: 'Test Suite Updated', value: 'test-suite-updated' }
    ];
  }
});

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app, value: app }))
  ];
});

const teamOptions = computed(() => {
  return [
    { label: 'All Teams', value: '' },
    ...teams.value.map(team => ({ label: team, value: team }))
  ];
});

const filteredExecutions = computed(() => {
  return testExecutions.value.filter(execution => {
    const matchesSearch = !searchQuery.value ||
      execution.suiteName.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesApp = !filterApplication.value || execution.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || execution.team === filterTeam.value;
    const matchesStatus = !filterType.value || execution.status === filterType.value;
    const matchesDate = (!filterDateFrom.value || new Date(execution.timestamp) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(execution.timestamp) <= new Date(filterDateTo.value));
    return matchesSearch && matchesApp && matchesTeam && matchesStatus && matchesDate;
  });
});

const filteredAuditLogs = computed(() => {
  return auditLogs.value.filter(log => {
    const matchesSearch = !searchQuery.value ||
      log.action.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      log.description.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || log.type === filterType.value;
    const matchesApp = !filterApplication.value || log.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || log.team === filterTeam.value;
    const matchesDate = (!filterDateFrom.value || new Date(log.timestamp) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(log.timestamp) <= new Date(filterDateTo.value));
    return matchesSearch && matchesType && matchesApp && matchesTeam && matchesDate;
  });
});

const filteredActivities = computed(() => {
  return activities.value.filter(activity => {
    const matchesSearch = !searchQuery.value ||
      activity.action.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      activity.details.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || activity.type === filterType.value;
    const matchesApp = !filterApplication.value || activity.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || activity.team === filterTeam.value;
    const matchesDate = (!filterDateFrom.value || new Date(activity.timestamp) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(activity.timestamp) <= new Date(filterDateTo.value));
    return matchesSearch && matchesType && matchesApp && matchesTeam && matchesDate;
  });
});

const loadData = async () => {
  loading.value = true;
  try {
    await Promise.all([
      loadExecutions(),
      loadAuditLogs(),
      loadActivities(),
    ]);
  } catch (error) {
    console.error('Error loading history data:', error);
  } finally {
    loading.value = false;
  }
};

const loadExecutions = async () => {
  try {
    const params = new URLSearchParams();
    if (filterApplication.value) params.append('application', filterApplication.value);
    if (filterTeam.value) params.append('team', filterTeam.value);
    if (filterType.value && activeTab.value === 'executions') params.append('status', filterType.value);
    if (filterDateFrom.value) params.append('dateFrom', filterDateFrom.value);
    if (filterDateTo.value) params.append('dateTo', filterDateTo.value);

    const response = await fetch(`${API_BASE_URL}/history/executions?${params.toString()}`);
    if (response.ok) {
      const data = await response.json();
      testExecutions.value = data.map((e: any) => ({
        ...e,
        timestamp: new Date(e.timestamp),
      }));
    }
  } catch (error) {
    console.error('Error loading test executions:', error);
  }
};

const loadAuditLogs = async () => {
  try {
    const params = new URLSearchParams();
    if (filterType.value && activeTab.value === 'audit') params.append('type', filterType.value);
    if (filterApplication.value) params.append('application', filterApplication.value);
    if (filterTeam.value) params.append('team', filterTeam.value);
    if (filterDateFrom.value) params.append('dateFrom', filterDateFrom.value);
    if (filterDateTo.value) params.append('dateTo', filterDateTo.value);

    const response = await fetch(`${API_BASE_URL}/history/audit-logs?${params.toString()}`);
    if (response.ok) {
      const data = await response.json();
      auditLogs.value = data.map((l: any) => ({
        ...l,
        timestamp: new Date(l.timestamp),
      }));
    }
  } catch (error) {
    console.error('Error loading audit logs:', error);
  }
};

const loadActivities = async () => {
  try {
    const params = new URLSearchParams();
    if (filterType.value && activeTab.value === 'activity') params.append('type', filterType.value);
    if (filterApplication.value) params.append('application', filterApplication.value);
    if (filterTeam.value) params.append('team', filterTeam.value);
    if (filterDateFrom.value) params.append('dateFrom', filterDateFrom.value);
    if (filterDateTo.value) params.append('dateTo', filterDateTo.value);

    const response = await fetch(`${API_BASE_URL}/history/activities?${params.toString()}`);
    if (response.ok) {
      const data = await response.json();
      activities.value = data.map((a: any) => ({
        ...a,
        timestamp: new Date(a.timestamp),
      }));
    }
  } catch (error) {
    console.error('Error loading activities:', error);
  }
};

const viewExecutionDetails = async (id: string) => {
  try {
    const response = await fetch(`${API_BASE_URL}/history/executions/${id}`);
    if (response.ok) {
      const execution = await response.json();
      selectedExecution.value = {
        ...execution,
        timestamp: new Date(execution.timestamp),
      };
      showExecutionModal.value = true;
    }
  } catch (error) {
    console.error('Error loading execution details:', error);
  }
};

const closeExecutionModal = () => {
  showExecutionModal.value = false;
  selectedExecution.value = null;
};

const selectForCompare = (id: string) => {
  if (selectedForCompare.value.length < 2) {
    selectedForCompare.value.push(id);
  }
};

const deselectForCompare = (id: string) => {
  selectedForCompare.value = selectedForCompare.value.filter(i => i !== id);
};

const compareExecutions = async () => {
  if (selectedForCompare.value.length !== 2) return;

  try {
    const response = await fetch(
      `${API_BASE_URL}/history/executions/${selectedForCompare.value[0]}/compare/${selectedForCompare.value[1]}`
    );
    if (response.ok) {
      comparisonData.value = await response.json();
      showComparisonModal.value = true;
    }
  } catch (error) {
    console.error('Error comparing executions:', error);
  }
};

const closeComparisonModal = () => {
  showComparisonModal.value = false;
  comparisonData.value = null;
  selectedForCompare.value = [];
};

const getLogIcon = (type: string) => {
  const icons: Record<string, any> = {
    'policy-change': Edit,
    'test-suite-change': TestTube,
    'report-generation': FileCheck,
    'violation-resolution': AlertTriangle,
    'user-action': User,
    'system-event': Settings
  };
  return icons[type] || FileText;
};

const getActivityIcon = (type: string) => {
  const icons: Record<string, any> = {
    'test-execution': Play,
    'policy-update': Shield,
    'report-generation': FileText,
    'violation-resolution': AlertTriangle,
    'test-suite-created': TestTube,
    'test-suite-updated': TestTube
  };
  return icons[type] || Activity;
};

const formatDateTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const formatRelativeTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
};

const formatDuration = (ms: number): string => {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

// Watch for tab changes and reload data
watch(activeTab, () => {
  loadData();
});

// Watch filters and reload data
watch([filterApplication, filterTeam, filterType, filterDateFrom, filterDateTo], () => {
  loadData();
}, { deep: true });

onMounted(() => {
  loadData();
});
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

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #a0aec0;
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
  transition: all 0.2s;
}

.timeline-item.selected-for-compare .timeline-content {
  border-color: rgba(79, 172, 254, 0.6);
  background: linear-gradient(135deg, rgba(79, 172, 254, 0.1) 0%, rgba(79, 172, 254, 0.05) 100%);
  box-shadow: 0 0 0 2px rgba(79, 172, 254, 0.3);
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

.timeline-actions {
  display: flex;
  gap: 8px;
}

.view-details-btn,
.compare-btn {
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
}

.view-details-btn:hover,
.compare-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.compare-btn.selected {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.6);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.compare-section {
  margin-top: 24px;
  padding: 20px;
  background: linear-gradient(135deg, rgba(79, 172, 254, 0.1) 0%, rgba(79, 172, 254, 0.05) 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  text-align: center;
}

.compare-execute-btn {
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.compare-execute-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
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

.log-user-action .audit-icon {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.log-system-event .audit-icon {
  background: rgba(139, 92, 246, 0.2);
  color: #8b5cf6;
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
