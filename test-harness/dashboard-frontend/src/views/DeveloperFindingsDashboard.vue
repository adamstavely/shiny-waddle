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
      v-if="selectedFinding"
      :isOpen="showDetailModal"
      :finding="selectedFinding"
      @update:isOpen="showDetailModal = false"
      @updated="loadDashboard"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import ComplianceScoreCard from '../components/ComplianceScoreCard.vue';
import FindingsTrendChart from '../components/FindingsTrendChart.vue';
import FindingDetailModal from '../components/FindingDetailModal.vue';
import { useAuth } from '../composables/useAuth';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'My Findings Dashboard', to: '/developer-findings' },
];

const loading = ref(true);
const error = ref<string | null>(null);
const dashboardData = ref<any>(null);
const selectedFinding = ref<any>(null);
const showDetailModal = ref(false);

const { user, getUserApplications, getUserTeams } = useAuth();

const loadDashboard = async () => {
  loading.value = true;
  error.value = null;
  try {
    // Build query params from user context
    const params: any = {};
    if (getUserApplications.value.length > 0) {
      params.applicationIds = getUserApplications.value.join(',');
    }
    if (getUserTeams.value.length > 0) {
      params.teamNames = getUserTeams.value.join(',');
    }

    const response = await axios.get('/api/unified-findings/dashboard/developer', { params });
    dashboardData.value = {
      ...response.data,
      recentFindings: response.data.recentFindings.map((f: any) => ({
        ...f,
        createdAt: new Date(f.createdAt),
        updatedAt: new Date(f.updatedAt),
      })),
    };
  } catch (err: any) {
    // Handle network errors gracefully
    if (err.code === 'ERR_NETWORK') {
      error.value = 'Network error. Please check your connection and try again.';
    } else if (err.response?.status === 401 || err.response?.status === 403) {
      error.value = 'You do not have permission to view this dashboard.';
    } else {
      error.value = err.response?.data?.message || 'Failed to load dashboard data';
    }
    console.error('Failed to load dashboard:', err);
  } finally {
    loading.value = false;
  }
};

const viewFinding = async (id: string) => {
  try {
    const response = await axios.get(`/api/unified-findings/${id}`);
    selectedFinding.value = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      updatedAt: new Date(response.data.updatedAt),
    };
    showDetailModal.value = true;
  } catch (err) {
    console.error('Failed to load finding:', err);
  }
};

const formatDate = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

onMounted(() => {
  loadDashboard();
});
</script>

<style scoped>
.developer-findings-dashboard {
  padding: 24px;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0;
}

.loading,
.error {
  padding: 24px;
  text-align: center;
  color: #ffffff;
}

.error {
  color: #fc8181;
}

.dashboard-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.summary-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.summary-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.summary-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
}

.summary-value.critical {
  color: #fc8181;
}

.summary-value.high {
  color: #fbbf24;
}

.summary-value.resolved {
  color: #22c55e;
}

.trends-section,
.recent-findings-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.trends-section h2,
.recent-findings-section h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 20px 0;
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
  padding: 12px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  color: #a0aec0;
  font-weight: 600;
  font-size: 0.875rem;
}

.findings-table td {
  padding: 12px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  color: #ffffff;
}

.finding-link {
  color: #4facfe;
  cursor: pointer;
  text-decoration: none;
}

.finding-link:hover {
  text-decoration: underline;
}

.severity-badge,
.status-badge {
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.severity-badge.severity-critical {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.severity-badge.severity-high {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.3);
}

.severity-badge.severity-medium {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.status-badge.status-open {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.status-badge.status-resolved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.btn-link {
  background: transparent;
  border: none;
  color: #4facfe;
  cursor: pointer;
  text-decoration: underline;
  font-size: 0.875rem;
}

.btn-link:hover {
  color: #00f2fe;
}
</style>

