<template>
  <div class="overview-tab">
    <div v-if="loading" class="loading">Loading dashboard data...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && dashboardData" class="overview-content">
      <!-- Executive Summary -->
      <ExecutiveSummary
        :overall-score="dashboardData.overallCompliance"
        :risk-score="executiveMetrics.riskScore"
        :remediation-velocity="executiveMetrics.remediationVelocity"
        :velocity-trend="executiveMetrics.velocityTrend"
        :roi-savings="executiveMetrics.roiSavings"
        :time-range="parseInt(sharedFilters.timeRange)"
      />

      <!-- Score Cards -->
      <div class="grid">
        <ScoreCard
          title="By Application"
          :scores="dashboardData.scoresByApplication"
          type="application"
          :icon="Building2"
        />
        <ScoreCard
          title="By Team"
          :scores="dashboardData.scoresByTeam"
          type="team"
          :icon="Users"
        />
        <CategoryScores
          :categories="getCategoryScores(dashboardData.scoresByApplication)"
        />
      </div>

      <!-- Test Results -->
      <div class="section">
        <TestResultsTable :results="dashboardData.recentTestResults" />
      </div>
      
      <!-- Validator Metrics -->
      <div class="section">
        <ValidatorMetrics :validators="validators" />
      </div>
      
      <!-- Test Battery & Harness Status -->
      <div class="section">
        <h2 class="section-title">
          <Battery class="section-icon" />
          Test Batteries & Harnesses
        </h2>
        <div class="battery-harness-grid">
          <div class="status-card">
            <div class="status-header">
              <Battery class="status-icon" />
              <h3>Test Batteries</h3>
            </div>
            <div class="status-content">
              <div class="status-stat">
                <span class="stat-value">{{ batteryStats.total }}</span>
                <span class="stat-label">Total Batteries</span>
              </div>
              <div class="status-stat">
                <span class="stat-value">{{ batteryStats.active }}</span>
                <span class="stat-label">Active</span>
              </div>
              <div class="status-stat">
                <span class="stat-value">{{ batteryStats.totalHarnesses }}</span>
                <span class="stat-label">Total Harnesses</span>
              </div>
            </div>
            <div class="status-actions">
              <button @click="navigateTo('/tests?tab=batteries')" class="btn-link-small">
                View All →
              </button>
            </div>
          </div>
          
          <div class="status-card">
            <div class="status-header">
              <Layers class="status-icon" />
              <h3>Test Harnesses</h3>
            </div>
            <div class="status-content">
              <div class="status-stat">
                <span class="stat-value">{{ harnessStats.total }}</span>
                <span class="stat-label">Total Harnesses</span>
              </div>
              <div class="status-stat">
                <span class="stat-value">{{ harnessStats.assigned }}</span>
                <span class="stat-label">Assigned to Apps</span>
              </div>
              <div class="status-stat">
                <span class="stat-value">{{ harnessStats.totalSuites }}</span>
                <span class="stat-label">Total Suites</span>
              </div>
            </div>
            <div class="status-actions">
              <button @click="navigateTo('/tests?tab=harnesses')" class="btn-link-small">
                View All →
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Trends Section -->
      <div class="trends-section">
        <h2 class="section-title">
          <TrendingUp class="section-icon" />
          Compliance Trends
        </h2>
        <div class="trends-grid">
          <div class="trend-card">
            <h3 class="trend-title">Overall Compliance</h3>
            <div class="trend-chart">
              <LineChart
                v-if="trendsData.overall.length > 0"
                :data="trendsData.overall"
                :height="200"
                color="#4facfe"
              />
              <div v-else class="no-data">No trend data available</div>
            </div>
            <div class="trend-stats">
              <span class="trend-change" :class="trendsData.overallChange >= 0 ? 'positive' : 'negative'">
                {{ trendsData.overallChange >= 0 ? '+' : '' }}{{ trendsData.overallChange }}%
              </span>
              <span class="trend-period">Last {{ sharedFilters.timeRange }} days</span>
            </div>
          </div>
          
          <div class="trend-card">
            <h3 class="trend-title">By Application</h3>
            <div class="trend-chart">
              <MultiLineChart
                v-if="Object.keys(trendsData.byApplication).length > 0"
                :data="trendsData.byApplication"
                :height="200"
              />
              <div v-else class="no-data">No trend data available</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Compliance Heatmap -->
      <div class="heatmap-section">
        <h2 class="section-title">
          <Grid3x3 class="section-icon" />
          Compliance Heatmap
        </h2>
        <div class="heatmap-container">
          <div class="heatmap-card">
            <div class="heatmap-header">
              <h3>Compliance by Application & Category</h3>
              <div class="heatmap-legend">
                <span class="legend-item">
                  <span class="legend-color" style="background: #22c55e;"></span>
                  High (90-100%)
                </span>
                <span class="legend-item">
                  <span class="legend-color" style="background: #fbbf24;"></span>
                  Medium (70-89%)
                </span>
                <span class="legend-item">
                  <span class="legend-color" style="background: #fc8181;"></span>
                  Low (&lt;70%)
                </span>
              </div>
            </div>
            <div class="heatmap-grid">
              <div class="heatmap-row">
                <div class="heatmap-label">Application</div>
                <div class="heatmap-label">Access Control</div>
                <div class="heatmap-label">Contracts</div>
                <div class="heatmap-label">Dataset Health</div>
              </div>
              <div
                v-for="(app, appName) in heatmapData"
                :key="appName"
                class="heatmap-row"
              >
                <div class="heatmap-app-name">{{ appName }}</div>
                <div
                  v-for="(score, category) in app.categories"
                  :key="category"
                  class="heatmap-cell"
                  :class="getHeatmapClass(score)"
                  :title="`${category}: ${score}%`"
                >
                  {{ score }}%
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="quick-actions-section">
        <h2 class="section-title">
          <Zap class="section-icon" />
          Quick Actions
        </h2>
        <div class="actions-grid">
          <button @click="navigateTo('/tests?tab=batteries')" class="action-card">
            <Battery class="action-icon" />
            <span class="action-label">Create Test Battery</span>
          </button>
          <button @click="navigateTo('/tests?tab=harnesses')" class="action-card">
            <Layers class="action-icon" />
            <span class="action-label">Create Test Harness</span>
          </button>
          <button @click="navigateTo('/tests/builder')" class="action-card">
            <TestTube class="action-icon" />
            <span class="action-label">Create Test Suite</span>
          </button>
          <button @click="navigateTo('/insights?tab=reports')" class="action-card">
            <FileText class="action-icon" />
            <span class="action-label">Generate Report</span>
          </button>
          <button @click="navigateTo('/policies')" class="action-card">
            <Shield class="action-icon" />
            <span class="action-label">Manage Policies</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue';
import { useRouter } from 'vue-router';
import axios from 'axios';
import { TestTube, FileText, Shield, BarChart3, TrendingUp, Grid3x3, Zap, Building2, Users, Battery, Layers } from 'lucide-vue-next';
import ScoreCard from '../../components/ScoreCard.vue';
import CategoryScores from '../../components/CategoryScores.vue';
import TestResultsTable from '../../components/TestResultsTable.vue';
import ValidatorMetrics from '../../components/ValidatorMetrics.vue';
import LineChart from '../../components/charts/LineChart.vue';
import MultiLineChart from '../../components/charts/MultiLineChart.vue';
import ExecutiveSummary from '../../components/insights/ExecutiveSummary.vue';
import { useRealtimeUpdates } from '../../composables/useRealtimeUpdates';

const props = defineProps<{
  sharedFilters: {
    timeRange: string;
    applications: string[];
    teams: string[];
    categories: string[];
  };
}>();

const emit = defineEmits<{
  'update-filters': [filters: any];
}>();

const router = useRouter();

interface DashboardData {
  overallCompliance: number;
  scoresByApplication: Record<string, any>;
  scoresByTeam: Record<string, any>;
  scoresByDataset: Record<string, any>;
  recentTestResults: any[];
  trends: any[];
}

const loading = ref(true);
const error = ref<string | null>(null);
const dashboardData = ref<DashboardData | null>(null);
const validators = ref<any[]>([]);
const testBatteries = ref<any[]>([]);
const testHarnesses = ref<any[]>([]);
const executiveMetrics = ref({
  riskScore: 45,
  remediationVelocity: 12,
  velocityTrend: 15,
  roiSavings: 125000
});

const batteryStats = computed(() => {
  const total = testBatteries.value.length;
  const active = testBatteries.value.filter(b => b.executionConfig).length;
  const totalHarnesses = testBatteries.value.reduce((sum, b) => sum + (b.harnessIds?.length || 0), 0);
  return { total, active, totalHarnesses };
});

const harnessStats = computed(() => {
  const total = testHarnesses.value.length;
  const assigned = testHarnesses.value.filter(h => h.applicationIds && h.applicationIds.length > 0).length;
  const totalSuites = testHarnesses.value.reduce((sum, h) => sum + (h.testSuiteIds?.length || 0), 0);
  return { total, assigned, totalSuites };
});

const trendsData = ref({
  overall: [] as Array<{ date: string; value: number }>,
  byApplication: {} as Record<string, Array<{ date: string; value: number }>>,
  overallChange: 0
});

const heatmapData = computed(() => {
  if (!dashboardData.value?.scoresByApplication) return {};
  
  const heatmap: Record<string, { categories: Record<string, number> }> = {};
  
  Object.entries(dashboardData.value.scoresByApplication).forEach(([appName, appData]: [string, any]) => {
    heatmap[appName] = {
      categories: {
        'Access Control': appData.scoresByCategory?.accessControl || 0,
        'Contracts': appData.scoresByCategory?.contracts || 0,
        'Dataset Health': appData.scoresByCategory?.datasetHealth || 0
      }
    };
  });
  
  return heatmap;
});

const loadBatteriesAndHarnesses = async () => {
  try {
    const [batteriesResponse, harnessesResponse] = await Promise.all([
      axios.get('/api/test-batteries'),
      axios.get('/api/test-harnesses'),
    ]);
    testBatteries.value = batteriesResponse.data || [];
    testHarnesses.value = harnessesResponse.data || [];
  } catch (err) {
    console.error('Error loading batteries and harnesses:', err);
    testBatteries.value = [];
    testHarnesses.value = [];
  }
};

const loadDashboard = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/dashboard-data');
    dashboardData.value = response.data;
    
    // Load trends data
    await loadTrends();
    
    // Load batteries and harnesses
    await loadBatteriesAndHarnesses();
    
    // Load executive metrics
    await loadExecutiveMetrics();
  } catch (err: any) {
    error.value = err.message || 'Failed to load dashboard data';
  } finally {
    loading.value = false;
  }
};

const loadTrends = async () => {
  try {
    const response = await axios.get('/api/analytics', {
      params: { timeRange: props.sharedFilters.timeRange }
    });
    
    const data = response.data.complianceTrends;
    if (data) {
      trendsData.value.overall = data.overall?.data || [];
      trendsData.value.byApplication = data.byApplication || {};
      trendsData.value.overallChange = data.overall?.change || 0;
    }
  } catch (err) {
    console.error('Error loading trends:', err);
    // Use empty data
    trendsData.value = {
      overall: [],
      byApplication: {},
      overallChange: 0
    };
  }
};

const loadExecutiveMetrics = async () => {
  try {
    const response = await axios.get('/api/executive-metrics', {
      params: { timeRange: props.sharedFilters.timeRange }
    });
    if (response.data) {
      executiveMetrics.value = response.data;
    }
  } catch (err) {
    console.error('Error loading executive metrics:', err);
    // Use default values
  }
};

const loadValidators = async () => {
  try {
    const response = await axios.get('/api/validators');
    validators.value = response.data;
  } catch (err) {
    console.error('Error loading validators:', err);
  }
};

const getCategoryScores = (scoresByApplication: Record<string, any>) => {
  if (!scoresByApplication || Object.keys(scoresByApplication).length === 0) {
    return {};
  }
  const firstApp = Object.values(scoresByApplication)[0];
  return firstApp.scoresByCategory || {};
};

const getHeatmapClass = (score: number): string => {
  if (score >= 90) return 'heatmap-high';
  if (score >= 70) return 'heatmap-medium';
  return 'heatmap-low';
};

const navigateTo = (path: string) => {
  router.push(path);
};

const handleRefresh = () => {
  loadDashboard();
};

// Watch for filter changes
watch(() => props.sharedFilters.timeRange, () => {
  loadTrends();
  loadExecutiveMetrics();
});

// Real-time updates
const { isConnected: isRealtimeConnected } = useRealtimeUpdates({
  onUpdate: (update) => {
    // Handle real-time updates
    if (update.type === 'test-result') {
      // Reload dashboard to get updated test results
      loadDashboard();
    } else if (update.type === 'compliance-score') {
      // Update compliance scores
      if (dashboardData.value) {
        if (update.data.applicationId && dashboardData.value.scoresByApplication) {
          const appData = dashboardData.value.scoresByApplication[update.data.applicationId];
          if (appData) {
            appData.overallScore = update.data.score;
            appData.lastUpdated = new Date(update.timestamp);
          }
        }
        if (update.data.overallCompliance !== undefined) {
          dashboardData.value.overallCompliance = update.data.overallCompliance;
        }
      }
    } else if (update.type === 'dashboard') {
      // Full dashboard update
      if (update.data) {
        dashboardData.value = update.data;
      }
    }
  },
  onError: (error) => {
    console.error('Real-time update error:', error);
  },
  autoReconnect: true,
});

let refreshInterval: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  loadDashboard();
  loadValidators();
  // Refresh every 30 seconds (as fallback if SSE is not connected)
  refreshInterval = setInterval(() => {
    if (!isRealtimeConnected.value) {
      loadDashboard();
      loadValidators();
    }
  }, 30000);
  
  // Listen for refresh event
  window.addEventListener('refresh-dashboard', handleRefresh);
});

onBeforeUnmount(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
  window.removeEventListener('refresh-dashboard', handleRefresh);
});
</script>

<style scoped>
.overview-tab {
  width: 100%;
}

.overview-content {
  max-width: 1400px;
  margin: 0 auto;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 30px;
  margin-bottom: 30px;
}

.loading {
  text-align: center;
  padding: 50px;
  color: #4facfe;
  font-size: 1.2em;
}

.error {
  text-align: center;
  padding: 20px;
  color: #fc8181;
  font-size: 1.2em;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  margin: 20px auto;
  max-width: 600px;
}

.section {
  margin-bottom: 40px;
  position: relative;
  z-index: 1;
}

.trends-section {
  margin-top: 40px;
  margin-bottom: 40px;
  position: relative;
  z-index: 1;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.section-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.trends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 24px;
}

.trend-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.trend-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.trend-chart {
  width: 100%;
  height: 200px;
  margin-bottom: 16px;
}

.no-data {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #a0aec0;
}

.trend-stats {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.trend-change {
  font-size: 1.125rem;
  font-weight: 600;
}

.trend-change.positive {
  color: #22c55e;
}

.trend-change.negative {
  color: #fc8181;
}

.trend-period {
  font-size: 0.875rem;
  color: #a0aec0;
}

.heatmap-section {
  margin-top: 40px;
}

.heatmap-container {
  width: 100%;
}

.heatmap-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.heatmap-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.heatmap-header h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.heatmap-legend {
  display: flex;
  gap: 16px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.legend-color {
  width: 16px;
  height: 16px;
  border-radius: 4px;
}

.heatmap-grid {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.heatmap-row {
  display: grid;
  grid-template-columns: 200px repeat(4, 1fr);
  gap: 12px;
  padding: 12px;
  border-radius: 8px;
}

.heatmap-row:first-child {
  background: rgba(79, 172, 254, 0.1);
  font-weight: 600;
}

.heatmap-label,
.heatmap-app-name {
  font-size: 0.875rem;
  color: #ffffff;
  font-weight: 500;
}

.heatmap-cell {
  text-align: center;
  padding: 8px;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
}

.heatmap-cell.heatmap-high {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.heatmap-cell.heatmap-medium {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.heatmap-cell.heatmap-low {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.quick-actions-section {
  margin-top: 40px;
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
}

.action-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 24px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  cursor: pointer;
  transition: all 0.3s;
}

.action-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
}

.action-label {
  font-size: 0.95rem;
  font-weight: 500;
  color: #ffffff;
}

/* Battery & Harness Status Styles */
.battery-harness-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.5rem;
}

.status-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.2s;
}

.status-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.15);
}

.status-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.25rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.status-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.status-header h3 {
  margin: 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
}

.status-content {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-bottom: 1rem;
}

.status-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #4facfe;
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.75rem;
  color: #a0aec0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.status-actions {
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-link-small {
  background: transparent;
  border: none;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  padding: 0;
  transition: color 0.2s;
}

.btn-link-small:hover {
  color: #00f2fe;
}
</style>

