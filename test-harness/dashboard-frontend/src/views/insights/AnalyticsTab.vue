<template>
  <div class="analytics-tab">
    <div class="page-header">
      <div class="header-content">
        <div>
          <h2 class="section-title">Analytics</h2>
          <p class="page-description">Compliance analytics and insights</p>
        </div>
        <div class="header-filters">
          <select v-model="timeRange" class="filter-select" @change="loadAnalytics">
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
            <option value="365">Last year</option>
          </select>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading analytics data...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error" class="analytics-content">
      <!-- Risk Trends Section (NEW) -->
      <section class="analytics-section">
        <h2 class="section-title">
          <AlertTriangle class="section-icon" />
          Risk Analysis
        </h2>
        <RiskTrends
          :current-risk="riskMetrics.currentRisk"
          :risk-trend="riskMetrics.riskTrend"
          :risk-data="riskMetrics.riskData"
          :risk-distribution="riskMetrics.riskDistribution"
          :top-risks="riskMetrics.topRisks"
        />
      </section>

      <!-- Compliance Trends Section -->
      <section class="analytics-section">
        <h2 class="section-title">
          <TrendingUp class="section-icon" />
          Compliance Trends
        </h2>
        <div class="charts-grid">
          <!-- Overall Compliance Trend -->
          <div class="chart-card">
            <h3 class="chart-title">Overall Compliance Score</h3>
            <div class="chart-container">
              <LineChart
                :data="complianceTrends.overall"
                :height="250"
                color="#4facfe"
              />
            </div>
            <div class="chart-stats">
              <div class="stat-item">
                <span class="stat-label">Current</span>
                <span class="stat-value">{{ complianceTrends.overall.current }}%</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">Change</span>
                <span class="stat-value" :class="complianceTrends.overall.change >= 0 ? 'positive' : 'negative'">
                  {{ complianceTrends.overall.change >= 0 ? '+' : '' }}{{ complianceTrends.overall.change }}%
                </span>
              </div>
            </div>
          </div>

          <!-- Trends by Application -->
          <div class="chart-card">
            <h3 class="chart-title">Trends by Application</h3>
            <div class="chart-container">
              <MultiLineChart
                :data="complianceTrends.byApplication"
                :height="250"
              />
            </div>
          </div>

          <!-- Trends by Team -->
          <div class="chart-card">
            <h3 class="chart-title">Trends by Team</h3>
            <div class="chart-container">
              <MultiLineChart
                :data="complianceTrends.byTeam"
                :height="250"
              />
            </div>
          </div>

          <!-- Trends by Category -->
          <div class="chart-card">
            <h3 class="chart-title">Trends by Category</h3>
            <div class="chart-container">
              <MultiLineChart
                :data="complianceTrends.byCategory"
                :height="250"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Score Analytics Section -->
      <section class="analytics-section">
        <h2 class="section-title">
          <BarChart3 class="section-icon" />
          Score Analytics
        </h2>
        <div class="charts-grid">
          <!-- Score Distribution -->
          <div class="chart-card">
            <h3 class="chart-title">Score Distribution</h3>
            <div class="chart-container">
              <DistributionChart
                :data="scoreAnalytics.distribution"
                :height="250"
              />
            </div>
          </div>

          <!-- Score Breakdown by Test Type -->
          <div class="chart-card">
            <h3 class="chart-title">Score Breakdown by Test Type</h3>
            <div class="chart-container">
              <BarChart
                :data="scoreAnalytics.byTestType"
                :height="250"
              />
            </div>
          </div>

          <!-- Score Comparison -->
          <div class="chart-card full-width">
            <h3 class="chart-title">Score Comparison Across Applications/Teams</h3>
            <div class="chart-container">
              <ComparisonChart
                :data="scoreAnalytics.comparison"
                :height="300"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Violation Patterns Section -->
      <section class="analytics-section">
        <h2 class="section-title">
          <AlertTriangle class="section-icon" />
          Violation Patterns
        </h2>
        <div class="charts-grid">
          <!-- Most Common Violations -->
          <div class="chart-card">
            <h3 class="chart-title">Most Common Violations</h3>
            <div class="chart-container">
              <BarChart
                :data="violationPatterns.mostCommon"
                :height="250"
                color="#fc8181"
              />
            </div>
          </div>

          <!-- Violation Frequency -->
          <div class="chart-card">
            <h3 class="chart-title">Violation Frequency</h3>
            <div class="chart-container">
              <LineChart
                :data="violationPatterns.frequency"
                :height="250"
                color="#fc8181"
              />
            </div>
          </div>

          <!-- Violation Trends -->
          <div class="chart-card">
            <h3 class="chart-title">Violation Trends</h3>
            <div class="chart-container">
              <MultiLineChart
                :data="violationPatterns.trends"
                :height="250"
              />
            </div>
          </div>

          <!-- Violation Correlation -->
          <div class="chart-card full-width">
            <h3 class="chart-title">Violation Correlation Analysis</h3>
            <div class="chart-container">
              <CorrelationChart
                :data="violationPatterns.correlation"
                :height="300"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- Performance Metrics Section -->
      <section class="analytics-section">
        <h2 class="section-title">
          <Gauge class="section-icon" />
          Performance Metrics
        </h2>
        <div class="charts-grid">
          <!-- Test Execution Time Trends -->
          <div class="chart-card">
            <h3 class="chart-title">Test Execution Time Trends</h3>
            <div class="chart-container">
              <LineChart
                :data="performanceMetrics.executionTime"
                :height="250"
                color="#00f2fe"
              />
            </div>
            <div class="chart-stats">
              <div class="stat-item">
                <span class="stat-label">Avg Time</span>
                <span class="stat-value">{{ performanceMetrics.executionTime.avg }}s</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">Trend</span>
                <span class="stat-value" :class="performanceMetrics.executionTime.trend >= 0 ? 'negative' : 'positive'">
                  {{ performanceMetrics.executionTime.trend >= 0 ? '+' : '' }}{{ performanceMetrics.executionTime.trend }}s
                </span>
              </div>
            </div>
          </div>

          <!-- Test Suite Performance -->
          <div class="chart-card">
            <h3 class="chart-title">Test Suite Performance</h3>
            <div class="chart-container">
              <BarChart
                :data="performanceMetrics.testSuite"
                :height="250"
                color="#22c55e"
              />
            </div>
          </div>

          <!-- Resource Usage -->
          <div class="chart-card">
            <h3 class="chart-title">Resource Usage Metrics</h3>
            <div class="chart-container">
              <ResourceUsageChart
                :data="performanceMetrics.resourceUsage"
                :height="250"
              />
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import axios from 'axios';
import { BarChart3, TrendingUp, AlertTriangle, Gauge } from 'lucide-vue-next';
import LineChart from '../../components/charts/LineChart.vue';
import MultiLineChart from '../../components/charts/MultiLineChart.vue';
import BarChart from '../../components/charts/BarChart.vue';
import DistributionChart from '../../components/charts/DistributionChart.vue';
import ComparisonChart from '../../components/charts/ComparisonChart.vue';
import CorrelationChart from '../../components/charts/CorrelationChart.vue';
import ResourceUsageChart from '../../components/charts/ResourceUsageChart.vue';
import RiskTrends from '../../components/insights/RiskTrends.vue';

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

const loading = ref(true);
const error = ref<string | null>(null);
const timeRange = ref(props.sharedFilters.timeRange || '30');

// Compliance Trends Data
const complianceTrends = ref({
  overall: {
    data: [] as Array<{ date: string; value: number }>,
    current: 0,
    change: 0
  },
  byApplication: {} as Record<string, Array<{ date: string; value: number }>>,
  byTeam: {} as Record<string, Array<{ date: string; value: number }>>,
  byCategory: {} as Record<string, Array<{ date: string; value: number }>>
});

// Score Analytics Data
const scoreAnalytics = ref({
  distribution: [] as Array<{ range: string; count: number }>,
  byTestType: [] as Array<{ name: string; value: number }>,
  comparison: [] as Array<{ name: string; applications: Record<string, number>; teams: Record<string, number> }>
});

// Violation Patterns Data
const violationPatterns = ref({
  mostCommon: [] as Array<{ name: string; value: number }>,
  frequency: {
    data: [] as Array<{ date: string; value: number }>
  },
  trends: {} as Record<string, Array<{ date: string; value: number }>>,
  correlation: [] as Array<{ violation1: string; violation2: string; correlation: number }>
});

// Performance Metrics Data
const performanceMetrics = ref({
  executionTime: {
    data: [] as Array<{ date: string; value: number }>,
    avg: 0,
    trend: 0
  },
  testSuite: [] as Array<{ name: string; value: number }>,
  resourceUsage: {
    cpu: [] as Array<{ date: string; value: number }>,
    memory: [] as Array<{ date: string; value: number }>,
    network: [] as Array<{ date: string; value: number }>
  }
});

// Risk Metrics Data
const riskMetrics = ref({
  currentRisk: 45,
  riskTrend: -5,
  riskData: [] as Array<{ date: string; value: number }>,
  riskDistribution: [] as Array<{ name: string; value: number }>,
  topRisks: [] as Array<{ name: string; severity: string; score: number }>
});

const loadAnalytics = async () => {
  try {
    loading.value = true;
    error.value = null;
    
    const response = await axios.get(`/api/analytics`, {
      params: { timeRange: timeRange.value }
    });
    
    const data = response.data;
    
    // Set compliance trends
    complianceTrends.value = data.complianceTrends || {
      overall: { data: [], current: 0, change: 0 },
      byApplication: {},
      byTeam: {},
      byCategory: {}
    };
    
    // Set score analytics
    scoreAnalytics.value = data.scoreAnalytics || {
      distribution: [],
      byTestType: [],
      comparison: []
    };
    
    // Set violation patterns
    violationPatterns.value = data.violationPatterns || {
      mostCommon: [],
      frequency: { data: [] },
      trends: {},
      correlation: []
    };
    
    // Set performance metrics
    performanceMetrics.value = data.performanceMetrics || {
      executionTime: { data: [], avg: 0, trend: 0 },
      testSuite: [],
      resourceUsage: { cpu: [], memory: [], network: [] }
    };
    
    // Load risk metrics
    await loadRiskMetrics();
    
    // Update shared filters
    emit('update-filters', { timeRange: timeRange.value });
  } catch (err: any) {
    console.error('Error loading analytics:', err);
    error.value = err.message || 'Failed to load analytics data';
    loadMockData();
  } finally {
    loading.value = false;
  }
};

const loadRiskMetrics = async () => {
  try {
    const response = await axios.get('/api/risk-metrics', {
      params: { timeRange: timeRange.value }
    });
    if (response.data) {
      riskMetrics.value = response.data;
    } else {
      // Use mock data
      generateMockRiskData();
    }
  } catch (err) {
    console.error('Error loading risk metrics:', err);
    generateMockRiskData();
  }
};

const generateMockRiskData = () => {
  const days = parseInt(timeRange.value);
  const dates = Array.from({ length: days }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (days - i - 1));
    return date.toISOString().split('T')[0];
  });
  
  riskMetrics.value = {
    currentRisk: 45,
    riskTrend: -5,
    riskData: dates.map((date, i) => ({
      date,
      value: 50 - (i * 0.1) + Math.random() * 5
    })),
    riskDistribution: [
      { name: 'Critical', value: 5 },
      { name: 'High', value: 12 },
      { name: 'Medium', value: 28 },
      { name: 'Low', value: 55 }
    ],
    topRisks: [
      { name: 'Unauthorized Data Access', severity: 'critical', score: 85 },
      { name: 'Policy Violation', severity: 'high', score: 72 },
      { name: 'Data Leakage Risk', severity: 'high', score: 68 },
      { name: 'Compliance Drift', severity: 'medium', score: 55 }
    ]
  };
};

const loadMockData = () => {
  const days = parseInt(timeRange.value);
  const dates = Array.from({ length: days }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (days - i - 1));
    return date.toISOString().split('T')[0];
  });
  
  const overallData = dates.map((date, i) => ({
    date,
    value: 75 + Math.sin(i / 5) * 10 + Math.random() * 5
  }));
  
  complianceTrends.value.overall = {
    data: overallData,
    current: Math.round(overallData[overallData.length - 1].value),
    change: Math.round((overallData[overallData.length - 1].value - overallData[0].value) * 10) / 10
  };
  
  complianceTrends.value.byApplication = {
    'research-tracker-api': dates.map((date, i) => ({
      date,
      value: 80 + Math.sin(i / 6) * 8 + Math.random() * 4
    })),
    'user-service': dates.map((date, i) => ({
      date,
      value: 70 + Math.sin(i / 7) * 10 + Math.random() * 5
    }))
  };
  
  scoreAnalytics.value.distribution = [
    { range: '0-50', count: 2 },
    { range: '50-60', count: 5 },
    { range: '60-70', count: 8 },
    { range: '70-80', count: 15 },
    { range: '80-90', count: 25 },
    { range: '90-100', count: 20 }
  ];
  
  violationPatterns.value.mostCommon = [
    { name: 'Unauthorized Access', value: 45 },
    { name: 'Data Leakage', value: 32 },
    { name: 'Policy Violation', value: 28 }
  ];
  
  generateMockRiskData();
};

// Watch for shared filter changes
watch(() => props.sharedFilters.timeRange, (newRange) => {
  if (newRange && newRange !== timeRange.value) {
    timeRange.value = newRange;
    loadAnalytics();
  }
});

onMounted(() => {
  loadAnalytics();
});
</script>

<style scoped>
.analytics-tab {
  width: 100%;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.header-filters {
  display: flex;
  gap: 12px;
  align-items: center;
}

.filter-select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s;
}

.filter-select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
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

.analytics-content {
  display: flex;
  flex-direction: column;
  gap: 40px;
}

.analytics-section {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.section-icon {
  width: 28px;
  height: 28px;
  color: #4facfe;
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
  gap: 24px;
}

.chart-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.3s;
}

.chart-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.chart-card.full-width {
  grid-column: 1 / -1;
}

.chart-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 20px;
}

.chart-container {
  width: 100%;
  margin-bottom: 16px;
}

.chart-stats {
  display: flex;
  gap: 24px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.stat-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.stat-value.positive {
  color: #22c55e;
}

.stat-value.negative {
  color: #fc8181;
}
</style>

