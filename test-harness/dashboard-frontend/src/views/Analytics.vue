<template>
  <div class="analytics-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Analytics</h1>
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
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { BarChart3, TrendingUp, AlertTriangle, Gauge } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import LineChart from '../components/charts/LineChart.vue';
import MultiLineChart from '../components/charts/MultiLineChart.vue';
import BarChart from '../components/charts/BarChart.vue';
import DistributionChart from '../components/charts/DistributionChart.vue';
import ComparisonChart from '../components/charts/ComparisonChart.vue';
import CorrelationChart from '../components/charts/CorrelationChart.vue';
import ResourceUsageChart from '../components/charts/ResourceUsageChart.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Analytics' }
];

const loading = ref(true);
const error = ref<string | null>(null);
const timeRange = ref('30');

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
  } catch (err: any) {
    console.error('Error loading analytics:', err);
    error.value = err.message || 'Failed to load analytics data';
    
    // Load mock data on error
    loadMockData();
  } finally {
    loading.value = false;
  }
};

const loadMockData = () => {
  // Generate mock compliance trends
  const days = parseInt(timeRange.value);
  const dates = Array.from({ length: days }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (days - i - 1));
    return date.toISOString().split('T')[0];
  });
  
  // Overall compliance trend
  const overallData = dates.map((date, i) => ({
    date,
    value: 75 + Math.sin(i / 5) * 10 + Math.random() * 5
  }));
  complianceTrends.value.overall = {
    data: overallData,
    current: Math.round(overallData[overallData.length - 1].value),
    change: Math.round((overallData[overallData.length - 1].value - overallData[0].value) * 10) / 10
  };
  
  // By application
  complianceTrends.value.byApplication = {
    'research-tracker-api': dates.map((date, i) => ({
      date,
      value: 80 + Math.sin(i / 6) * 8 + Math.random() * 4
    })),
    'user-service': dates.map((date, i) => ({
      date,
      value: 70 + Math.sin(i / 7) * 10 + Math.random() * 5
    })),
    'data-pipeline': dates.map((date, i) => ({
      date,
      value: 85 + Math.sin(i / 5) * 7 + Math.random() * 3
    }))
  };
  
  // By team
  complianceTrends.value.byTeam = {
    'research-platform': dates.map((date, i) => ({
      date,
      value: 82 + Math.sin(i / 6) * 8 + Math.random() * 4
    })),
    'platform-team': dates.map((date, i) => ({
      date,
      value: 72 + Math.sin(i / 7) * 10 + Math.random() * 5
    })),
    'data-engineering': dates.map((date, i) => ({
      date,
      value: 88 + Math.sin(i / 5) * 6 + Math.random() * 3
    }))
  };
  
  // By category
  complianceTrends.value.byCategory = {
    'Access Control': dates.map((date, i) => ({
      date,
      value: 90 + Math.sin(i / 6) * 5 + Math.random() * 3
    })),
    'Data Behavior': dates.map((date, i) => ({
      date,
      value: 75 + Math.sin(i / 7) * 8 + Math.random() * 4
    })),
    'Contracts': dates.map((date, i) => ({
      date,
      value: 80 + Math.sin(i / 5) * 7 + Math.random() * 3
    })),
    'Dataset Health': dates.map((date, i) => ({
      date,
      value: 85 + Math.sin(i / 6) * 6 + Math.random() * 4
    }))
  };
  
  // Score distribution
  scoreAnalytics.value.distribution = [
    { range: '0-50', count: 2 },
    { range: '50-60', count: 5 },
    { range: '60-70', count: 8 },
    { range: '70-80', count: 15 },
    { range: '80-90', count: 25 },
    { range: '90-100', count: 20 }
  ];
  
  // By test type
  scoreAnalytics.value.byTestType = [
    { name: 'Access Control', value: 90 },
    { name: 'Data Behavior', value: 75 },
    { name: 'Contracts', value: 80 },
    { name: 'Dataset Health', value: 85 },
    { name: 'API Security', value: 78 }
  ];
  
  // Comparison
  scoreAnalytics.value.comparison = [
    {
      name: 'Q1',
      applications: {
        'research-tracker-api': 85,
        'user-service': 72,
        'data-pipeline': 88
      },
      teams: {
        'research-platform': 82,
        'platform-team': 72,
        'data-engineering': 88
      }
    },
    {
      name: 'Q2',
      applications: {
        'research-tracker-api': 87,
        'user-service': 75,
        'data-pipeline': 90
      },
      teams: {
        'research-platform': 84,
        'platform-team': 74,
        'data-engineering': 90
      }
    }
  ];
  
  // Most common violations
  violationPatterns.value.mostCommon = [
    { name: 'Unauthorized Access', value: 45 },
    { name: 'Data Leakage', value: 32 },
    { name: 'Policy Violation', value: 28 },
    { name: 'Contract Breach', value: 22 },
    { name: 'Privacy Threshold', value: 18 }
  ];
  
  // Violation frequency
  violationPatterns.value.frequency = {
    data: dates.map((date, i) => ({
      date,
      value: 10 + Math.sin(i / 4) * 5 + Math.random() * 3
    }))
  };
  
  // Violation trends
  violationPatterns.value.trends = {
    'Unauthorized Access': dates.map((date, i) => ({
      date,
      value: 15 + Math.sin(i / 5) * 5 + Math.random() * 3
    })),
    'Data Leakage': dates.map((date, i) => ({
      date,
      value: 10 + Math.sin(i / 6) * 4 + Math.random() * 2
    })),
    'Policy Violation': dates.map((date, i) => ({
      date,
      value: 8 + Math.sin(i / 7) * 3 + Math.random() * 2
    }))
  };
  
  // Correlation
  violationPatterns.value.correlation = [
    { violation1: 'Unauthorized Access', violation2: 'Data Leakage', correlation: 0.75 },
    { violation1: 'Policy Violation', violation2: 'Contract Breach', correlation: 0.68 },
    { violation1: 'Data Leakage', violation2: 'Privacy Threshold', correlation: 0.62 }
  ];
  
  // Execution time
  const execData = dates.map((date, i) => ({
    date,
    value: 5 + Math.sin(i / 8) * 2 + Math.random() * 1
  }));
  performanceMetrics.value.executionTime = {
    data: execData,
    avg: Math.round(execData.reduce((sum, d) => sum + d.value, 0) / execData.length * 10) / 10,
    trend: Math.round((execData[execData.length - 1].value - execData[0].value) * 10) / 10
  };
  
  // Test suite performance
  performanceMetrics.value.testSuite = [
    { name: 'Access Control Suite', value: 92 },
    { name: 'Data Behavior Suite', value: 78 },
    { name: 'Contract Suite', value: 85 },
    { name: 'Dataset Health Suite', value: 88 }
  ];
  
  // Resource usage
  performanceMetrics.value.resourceUsage = {
    cpu: dates.map((date, i) => ({
      date,
      value: 40 + Math.sin(i / 6) * 15 + Math.random() * 5
    })),
    memory: dates.map((date, i) => ({
      date,
      value: 50 + Math.sin(i / 7) * 20 + Math.random() * 8
    })),
    network: dates.map((date, i) => ({
      date,
      value: 30 + Math.sin(i / 5) * 10 + Math.random() * 4
    }))
  };
};

onMounted(() => {
  loadAnalytics();
});
</script>

<style scoped>
.analytics-page {
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

.section-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
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
