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
      
      <!-- Trends Section -->
      <div class="trends-section">
        <h2 class="section-title">Compliance Trends</h2>
        <div class="trends-grid">
          <div class="trend-card">
            <h3 class="trend-title">Overall Compliance</h3>
            <div class="trend-chart">
              <svg class="chart-svg" viewBox="0 0 400 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="trendGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.3" />
                    <stop offset="100%" style="stop-color:#4facfe;stop-opacity:0" />
                  </linearGradient>
                </defs>
                <polyline
                  points="0,180 50,160 100,150 150,140 200,130 250,125 300,120 350,115 400,110"
                  fill="url(#trendGradient)"
                  stroke="#4facfe"
                  stroke-width="2"
                />
              </svg>
            </div>
            <div class="trend-stats">
              <span class="trend-change positive">+5.2%</span>
              <span class="trend-period">Last 30 days</span>
            </div>
          </div>
          
          <div class="trend-card">
            <h3 class="trend-title">By Application</h3>
            <div class="trend-chart">
              <svg class="chart-svg" viewBox="0 0 400 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="appGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#00f2fe;stop-opacity:0.3" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:0" />
                  </linearGradient>
                </defs>
                <polyline
                  points="0,170 50,165 100,160 150,155 200,150 250,145 300,140 350,135 400,130"
                  fill="url(#appGradient)"
                  stroke="#00f2fe"
                  stroke-width="2"
                />
              </svg>
            </div>
            <div class="trend-stats">
              <span class="trend-change positive">+3.8%</span>
              <span class="trend-period">Last 30 days</span>
            </div>
          </div>
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
  // Refresh every 30 seconds
  setInterval(loadDashboard, 30000);
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

