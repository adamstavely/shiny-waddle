<template>
  <div class="compliance-dashboard">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Compliance Dashboard</h1>
          <p class="page-description">Monitor policy compliance and track remediation progress</p>
        </div>
        <div class="header-actions">
          <button @click="refreshAll" :disabled="loading" class="btn-secondary">
            <RefreshCw class="btn-icon" :class="{ spinning: loading }" />
            Refresh
          </button>
          <button @click="exportReport" :disabled="!overview" class="btn-primary">
            <Download class="btn-icon" />
            Export Report
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading && !overview" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading compliance data...</p>
    </div>

    <!-- Error State -->
    <div v-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadDashboard" class="btn-retry">Retry</button>
    </div>

    <!-- Overview Cards -->
    <div v-if="overview" class="overview-cards">
      <OverviewCard
        title="Total Policies"
        :value="overview.totalPolicies"
        icon="Shield"
        :status="'info'"
      />
      <OverviewCard
        title="Compliance Score"
        :value="`${overview.complianceScore}%`"
        :status="getComplianceStatus(overview.complianceScore)"
        icon="Gauge"
      />
      <OverviewCard
        title="Total Gaps"
        :value="overview.totalGaps"
        :status="overview.totalGaps > 0 ? 'warning' : 'success'"
        icon="AlertCircle"
      />
      <OverviewCard
        title="Critical Gaps"
        :value="overview.criticalGaps"
        :status="overview.criticalGaps > 0 ? 'error' : 'success'"
        icon="AlertTriangle"
      />
    </div>

    <!-- Gap Analysis -->
    <div v-if="overview" class="gap-analysis-section">
      <GapAnalysisView />
    </div>

    <!-- Compliance Trends -->
    <div class="trends-section">
      <ComplianceTrendsChart />
    </div>

    <!-- Scheduled Reports -->
    <div class="scheduled-reports-section">
      <ScheduledReports />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  Shield,
  Gauge,
  AlertCircle,
  AlertTriangle,
  RefreshCw,
  Download
} from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import GapAnalysisView from '../../components/policies/GapAnalysisView.vue';
import OverviewCard from '../../components/policies/OverviewCard.vue';
import ComplianceTrendsChart from '../../components/policies/ComplianceTrendsChart.vue';
import ScheduledReports from '../../components/policies/ScheduledReports.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies/access-control' },
  { label: 'Compliance Dashboard' }
];

interface ComplianceOverview {
  totalPolicies: number;
  complianceScore: number;
  totalGaps: number;
  criticalGaps: number;
  highGaps: number;
  mediumGaps: number;
  lowGaps: number;
}

const overview = ref<ComplianceOverview | null>(null);
const trendsData = ref<any[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);

const getComplianceStatus = (score: number): 'success' | 'warning' | 'error' => {
  if (score >= 90) return 'success';
  if (score >= 70) return 'warning';
  return 'error';
};

const loadDashboard = async () => {
  loading.value = true;
  error.value = null;

  try {
    // Load compliance overview
    const complianceResponse = await axios.get('/api/policies/compliance-analysis');
    const compliance = complianceResponse.data;

    // Calculate overview from compliance analysis
    overview.value = {
      totalPolicies: compliance.totalPolicies || 0,
      complianceScore: compliance.compliancePercentage || 0,
      totalGaps: compliance.gaps?.length || 0,
      criticalGaps: compliance.summary?.critical || 0,
      highGaps: compliance.summary?.high || 0,
      mediumGaps: compliance.summary?.medium || 0,
      lowGaps: compliance.summary?.low || 0,
    };

    // Load trends (placeholder - would need historical data)
    trendsData.value = [];
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load compliance dashboard';
    console.error('Error loading compliance dashboard:', err);
  } finally {
    loading.value = false;
  }
};

const refreshAll = async () => {
  await loadDashboard();
};

const exportReport = () => {
  if (!overview.value) return;

  const report = {
    generatedAt: new Date().toISOString(),
    overview: overview.value,
    trends: trendsData.value,
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `compliance-report-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
};

onMounted(() => {
  loadDashboard();
});
</script>

<style scoped>
.compliance-dashboard {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-lg);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
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

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.btn-secondary {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-primary);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.btn-primary:disabled,
.btn-secondary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.overview-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.gap-analysis-section {
  margin-bottom: var(--spacing-xl);
}

.trends-section,
.scheduled-reports-section {
  margin-bottom: var(--spacing-xl);
}

.trends-section h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.trends-chart {
  padding: var(--spacing-xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  min-height: 300px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.trends-placeholder {
  color: var(--color-text-secondary);
  font-style: italic;
}

.loading-state,
.error-state {
  text-align: center;
  padding: var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  margin: 0 auto var(--spacing-md);
  animation: spin 1s linear infinite;
}

.error-icon {
  width: 64px;
  height: 64px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-lg);
}

.error-state {
  color: var(--color-error);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}
</style>
