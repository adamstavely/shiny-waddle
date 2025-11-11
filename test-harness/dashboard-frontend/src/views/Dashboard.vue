<template>
  <div class="dashboard-view">
    <Breadcrumb :items="breadcrumbItems" />
    <div v-if="loading" class="loading">Loading dashboard data...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && dashboardData" class="dashboard">
      <OverallScore :score="dashboardData.overallCompliance" />
      <div class="grid">
        <ScoreCard
          title="By Application"
          :scores="dashboardData.scoresByApplication"
          type="application"
        />
        <ScoreCard
          title="By Team"
          :scores="dashboardData.scoresByTeam"
          type="team"
        />
        <CategoryScores
          :categories="getCategoryScores(dashboardData.scoresByApplication)"
        />
      </div>
      <TestResultsTable :results="dashboardData.recentTestResults" />
      
      <!-- Validator Metrics -->
      <ValidatorMetrics :validators="validators" />
      
      <!-- Trends Section -->
      <div class="trends-section">
        <h2 class="section-title">Compliance Trends</h2>
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
              <span class="trend-period">Last 30 days</span>
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
        <h2 class="section-title">Compliance Heatmap</h2>
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
                <div class="heatmap-label">Data Behavior</div>
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
        <h2 class="section-title">Quick Actions</h2>
        <div class="actions-grid">
          <button @click="navigateTo('/tests/builder')" class="action-card">
            <TestTube class="action-icon" />
            <span class="action-label">Create Test Suite</span>
          </button>
          <button @click="navigateTo('/reports')" class="action-card">
            <FileText class="action-icon" />
            <span class="action-label">Generate Report</span>
          </button>
          <button @click="navigateTo('/policies')" class="action-card">
            <Shield class="action-icon" />
            <span class="action-label">Manage Policies</span>
          </button>
          <button @click="navigateTo('/analytics')" class="action-card">
            <BarChart3 class="action-icon" />
            <span class="action-label">View Analytics</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue';
import axios from 'axios';
import { LayoutDashboard } from 'lucide-vue-next';
import OverallScore from '../components/OverallScore.vue';
import ScoreCard from '../components/ScoreCard.vue';
import CategoryScores from '../components/CategoryScores.vue';
import TestResultsTable from '../components/TestResultsTable.vue';
import ValidatorMetrics from '../components/ValidatorMetrics.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Dashboard', icon: LayoutDashboard }
];

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

const loadDashboard = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/dashboard-data');
    dashboardData.value = response.data;
  } catch (err: any) {
    error.value = err.message || 'Failed to load dashboard data';
  } finally {
    loading.value = false;
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

const handleRefresh = () => {
  loadDashboard();
};

onMounted(() => {
  loadDashboard();
  loadValidators();
  // Refresh every 30 seconds
  setInterval(() => {
    loadDashboard();
    loadValidators();
  }, 30000);
  // Listen for refresh event from TopNav
  window.addEventListener('refresh-dashboard', handleRefresh);
});

onBeforeUnmount(() => {
  window.removeEventListener('refresh-dashboard', handleRefresh);
});
</script>

<style scoped>
.dashboard-view {
  width: 100%;
}

.dashboard {
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

.trends-section {
  margin-top: 40px;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
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

.chart-svg {
  width: 100%;
  height: 100%;
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
</style>

