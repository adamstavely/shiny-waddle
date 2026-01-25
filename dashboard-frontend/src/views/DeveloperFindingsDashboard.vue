<template>
  <div class="developer-findings-dashboard">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">My Findings Dashboard</h1>
          <p class="page-description">View your security findings and compliance trends</p>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading dashboard data...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error && dashboardData" class="dashboard-content">
      <!-- Compliance Score Card -->
      <ComplianceScoreCard
        :currentScore="dashboardData.currentScore"
        :previousScore="dashboardData.previousScore"
        :trend="dashboardData.trend"
        :scoreChange="dashboardData.scoreChange"
      />

      <!-- Findings Summary Cards -->
      <div class="summary-grid">
        <div class="summary-card">
          <div class="summary-label">Total Findings</div>
          <div class="summary-value">{{ dashboardData.findings.total }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Critical</div>
          <div class="summary-value critical">{{ dashboardData.findings.bySeverity.critical || 0 }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">High</div>
          <div class="summary-value high">{{ dashboardData.findings.bySeverity.high || 0 }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Open</div>
          <div class="summary-value">{{ dashboardData.findings.byStatus.open || 0 }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Resolved</div>
          <div class="summary-value resolved">{{ dashboardData.findings.byStatus.resolved || 0 }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">In Progress</div>
          <div class="summary-value">{{ dashboardData.findings.byStatus['in-progress'] || 0 }}</div>
        </div>
      </div>

      <!-- Trends Chart -->
      <div class="trends-section">
        <h2>Compliance Score Over Time</h2>
        <FindingsTrendChart :trends="dashboardData.trends" />
      </div>

      <!-- Recent Findings -->
      <div class="recent-findings-section">
        <h2>Recent Findings</h2>
        <div class="findings-table">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Source</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="finding in dashboardData.recentFindings" :key="finding.id">
                <td>
                  <a @click="viewFinding(finding.id)" class="finding-link">{{ finding.title }}</a>
                </td>
                <td>
                  <span :class="`severity-badge severity-${finding.severity}`">
                    {{ finding.severity }}
                  </span>
                </td>
                <td>
                  <span :class="`status-badge status-${finding.status}`">
                    {{ finding.status }}
                  </span>
                </td>
                <td>{{ finding.source.toUpperCase() }}</td>
                <td>{{ formatDate(finding.createdAt) }}</td>
                <td>
                  <button @click="viewFinding(finding.id)" class="btn-link">View</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Finding Detail Modal -->
    <FindingDetailModal
      v-if="findingModal.data.value"
      :isOpen="findingModal.isOpen.value"
      :finding="findingModal.data.value"
      @update:isOpen="findingModal.close()"
      @updated="reload"
    />
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import ComplianceScoreCard from '../components/ComplianceScoreCard.vue';
import FindingsTrendChart from '../components/FindingsTrendChart.vue';
import FindingDetailModal from '../components/FindingDetailModal.vue';
import { useAuth } from '../composables/useAuth';
import { useApiDataAuto } from '../composables/useApiData';
import { useModal } from '../composables/useModal';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'My Findings Dashboard', to: '/developer-findings' },
];

const { user, getUserApplications, getUserTeams } = useAuth();

// Use composable for API data fetching
const { data: dashboardData, loading, error, reload } = useApiDataAuto(
  async () => {
    // Build query params from user context
    const params: any = {};
    if (getUserApplications.value.length > 0) {
      params.applicationIds = getUserApplications.value.join(',');
    }
    if (getUserTeams.value.length > 0) {
      params.teamNames = getUserTeams.value.join(',');
    }

    const response = await axios.get('/api/unified-findings/dashboard/developer', { params });
    return {
      ...response.data,
      recentFindings: response.data.recentFindings.map((f: any) => ({
        ...f,
        createdAt: new Date(f.createdAt),
        updatedAt: new Date(f.updatedAt),
      })),
    };
  },
  {
    initialData: null,
    errorMessage: 'Failed to load dashboard data',
    onError: (err: any) => {
      // Handle network errors gracefully
      if (err.code === 'ERR_NETWORK') {
        return 'Network error. Please check your connection and try again.';
      } else if (err.response?.status === 401 || err.response?.status === 403) {
        return 'You do not have permission to view this dashboard.';
      }
      return err.response?.data?.message || 'Failed to load dashboard data';
    },
  }
);

// Use composable for modal state management
const findingModal = useModal<any>();

const viewFinding = async (id: string) => {
  try {
    const response = await axios.get(`/api/unified-findings/${id}`);
    const finding = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      updatedAt: new Date(response.data.updatedAt),
    };
    findingModal.open(finding);
  } catch (err) {
    console.error('Failed to load finding:', err);
  }
};

const formatDate = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

// Note: useApiDataAuto automatically loads on mount, so no need for onMounted
</script>

<style scoped>
.developer-findings-dashboard {
  padding: var(--spacing-lg);
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.loading,
.error {
  padding: var(--spacing-lg);
  text-align: center;
  color: var(--color-text-primary);
}

.error {
  color: var(--color-error);
}

.dashboard-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.summary-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  text-align: center;
}

.summary-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-sm);
}

.summary-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.summary-value.critical {
  color: var(--color-error);
}

.summary-value.high {
  color: var(--color-warning);
}

.summary-value.resolved {
  color: var(--color-success);
}

.trends-section,
.recent-findings-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.trends-section h2,
.recent-findings-section h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xl) 0;
}

.findings-table {
  overflow-x: auto;
}

.findings-table table {
  width: 100%;
  border-collapse: collapse;
}

.findings-table th {
  text-align: left;
  padding: var(--spacing-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-sm);
}

.findings-table td {
  padding: var(--spacing-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
  color: var(--color-text-primary);
}

.finding-link {
  color: var(--color-primary);
  cursor: pointer;
  text-decoration: none;
}

.finding-link:hover {
  text-decoration: underline;
}

.severity-badge,
.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}

.severity-badge.severity-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
}

.severity-badge.severity-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
  border: var(--border-width-thin) solid var(--color-warning);
}

.severity-badge.severity-medium {
  background: var(--border-color-muted);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
}

.status-badge.status-open {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
}

.status-badge.status-resolved {
  background: var(--color-success-bg);
  color: var(--color-success);
  border: var(--border-width-thin) solid var(--color-success);
}

.btn-link {
  background: transparent;
  border: none;
  color: var(--color-primary);
  cursor: pointer;
  text-decoration: underline;
  font-size: var(--font-size-sm);
}

.btn-link:hover {
  color: var(--color-secondary);
}
</style>

