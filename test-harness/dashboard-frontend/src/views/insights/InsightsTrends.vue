<template>
  <div class="insights-trends-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Trends</h1>
          <p class="page-description">Compliance trends and historical analysis</p>
        </div>
        <div class="trend-filters">
          <Dropdown
            v-model="trendFilterApplication"
            :options="applicationOptions"
            placeholder="All Applications"
            class="filter-dropdown"
          />
          <input
            v-model="trendDays"
            type="number"
            min="7"
            max="365"
            placeholder="Days"
            class="filter-input"
          />
        </div>
      </div>
    </div>

    <div class="trends-container">
      <div class="trend-section">
        <h3 class="trend-title">Overall Compliance Trend</h3>
        <ComplianceTrendChart
          :application-id="trendFilterApplication || undefined"
          :days="trendDays || 30"
        />
      </div>
      <div class="trend-section">
        <h3 class="trend-title">Posture Trends by Domain</h3>
        <div class="domain-charts-grid">
          <div class="domain-chart-item">
            <h4 class="domain-chart-title">Data Contracts</h4>
            <DomainTrendChart
              domain="Data Contracts"
              :application-id="trendFilterApplication || undefined"
              :days="trendDays || 30"
            />
          </div>
          <div class="domain-chart-item">
            <h4 class="domain-chart-title">IAM</h4>
            <DomainTrendChart
              domain="IAM"
              :application-id="trendFilterApplication || undefined"
              :days="trendDays || 30"
            />
          </div>
          <div class="domain-chart-item">
            <h4 class="domain-chart-title">API Security</h4>
            <DomainTrendChart
              domain="API Security"
              :application-id="trendFilterApplication || undefined"
              :days="trendDays || 30"
            />
          </div>
          <div class="domain-chart-item">
            <h4 class="domain-chart-title">Platform Config</h4>
            <DomainTrendChart
              domain="Platform Config"
              :application-id="trendFilterApplication || undefined"
              :days="trendDays || 30"
            />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import axios from 'axios';
import Breadcrumb from '../../components/Breadcrumb.vue';
import Dropdown from '../../components/Dropdown.vue';
import ComplianceTrendChart from '../../components/ComplianceTrendChart.vue';
import DomainTrendChart from '../../components/DomainTrendChart.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights & Reports', to: '/insights' },
  { label: 'Trends' }
];

const trendFilterApplication = ref('');
const trendDays = ref(30);
const applications = ref<any[]>([]);

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app.name, value: app.id }))
  ];
});

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/v1/applications');
    applications.value = response.data || [];
  } catch (err) {
    console.error('Error loading applications:', err);
  }
};

onMounted(() => {
  loadApplications();
});
</script>

<style scoped>
.insights-trends-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
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
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
}

.trend-filters {
  display: flex;
  gap: 12px;
  align-items: center;
}

.filter-dropdown {
  min-width: 200px;
}

.filter-input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  width: 100px;
}

.trends-container {
  display: flex;
  flex-direction: column;
  gap: 32px;
}

.trend-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.trend-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
}

.domain-charts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
}

.domain-chart-item {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 8px;
  padding: 16px;
}

.domain-chart-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}
</style>
