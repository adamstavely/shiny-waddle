<template>
  <div class="results-list-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Results</h1>
          <p class="page-description">View Salesforce Experience Cloud test execution results</p>
        </div>
        <div class="header-filters">
          <select v-model="selectedConfigId" @change="loadResults" class="filter-select">
            <option value="">All Configurations</option>
            <option v-for="config in configs" :key="config.id" :value="config.id">
              {{ config.name }}
            </option>
          </select>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading results...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error" class="results-container">
      <div v-if="results.length === 0" class="empty-state">
        <BarChart3 class="empty-icon" />
        <p>No test results found</p>
        <router-link to="/salesforce-experience-cloud" class="btn-primary">
          Create Configuration
        </router-link>
      </div>

      <div v-else class="results-table-container">
        <table class="results-table">
          <thead>
            <tr>
              <th>Test Name</th>
              <th>Configuration</th>
              <th>Test Type</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Timestamp</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="result in results" :key="result.id" class="result-row">
              <td>
                <strong>{{ result.testName }}</strong>
              </td>
              <td>
                <span class="config-name">{{ getConfigName(result.configId) }}</span>
              </td>
              <td>
                <span class="test-type-badge">{{ result.testType }}</span>
              </td>
              <td>
                <span class="status-badge" :class="getStatusClass(result.status)">
                  <CheckCircle2 v-if="result.status === 'passed'" class="status-icon" />
                  <XCircle v-else-if="result.status === 'failed'" class="status-icon" />
                  <AlertCircle v-else class="status-icon" />
                  {{ result.status.toUpperCase() }}
                </span>
              </td>
              <td>
                <div v-if="result.summary" class="findings-summary">
                  <span v-if="result.summary.criticalCount > 0" class="finding-count critical">
                    {{ result.summary.criticalCount }} Critical
                  </span>
                  <span v-if="result.summary.highCount > 0" class="finding-count high">
                    {{ result.summary.highCount }} High
                  </span>
                  <span v-if="result.summary.mediumCount > 0" class="finding-count medium">
                    {{ result.summary.mediumCount }} Medium
                  </span>
                  <span v-else-if="result.summary.totalFindings === 0" class="finding-count none">
                    No findings
                  </span>
                </div>
                <span v-else class="finding-count">-</span>
              </td>
              <td>
                <span class="timestamp">{{ formatDate(result.timestamp) }}</span>
              </td>
              <td>
                <button @click="viewResult(result.id)" class="btn-link">
                  View Details
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { BarChart3, CheckCircle2, XCircle, AlertCircle } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import { useSalesforceExperienceCloud } from '../../composables/useSalesforceExperienceCloud';
import type { SalesforceExperienceCloudConfigEntity, SalesforceExperienceCloudTestResultEntity } from '../../types/salesforce-experience-cloud';

const route = useRoute();
const { loading, error, getResults, getConfigs } = useSalesforceExperienceCloud();

const results = ref<SalesforceExperienceCloudTestResultEntity[]>([]);
const configs = ref<SalesforceExperienceCloudConfigEntity[]>([]);
const selectedConfigId = ref<string>((route.query.configId as string) || '');

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Salesforce Experience Cloud', to: '/salesforce-experience-cloud' },
  { label: 'Results', to: '' },
];

const loadResults = async () => {
  try {
    results.value = await getResults(selectedConfigId.value || undefined);
    // Sort by timestamp descending
    results.value.sort((a, b) => {
      const dateA = new Date(a.timestamp).getTime();
      const dateB = new Date(b.timestamp).getTime();
      return dateB - dateA;
    });
  } catch (err) {
    console.error('Failed to load results:', err);
  }
};

const loadConfigs = async () => {
  try {
    configs.value = await getConfigs();
  } catch (err) {
    console.error('Failed to load configurations:', err);
  }
};

const getConfigName = (configId: string) => {
  const config = configs.value.find(c => c.id === configId);
  return config?.name || configId;
};

const viewResult = (id: string) => {
  window.location.href = `/salesforce-experience-cloud/results/${id}`;
};

const getStatusClass = (status: string) => {
  return {
    'status-passed': status === 'passed',
    'status-failed': status === 'failed',
    'status-warning': status === 'warning',
  };
};

const formatDate = (date: Date | string) => {
  return new Date(date).toLocaleString();
};

onMounted(() => {
  loadConfigs();
  loadResults();
});
</script>

<style scoped>
.results-list-page {
  padding: 2rem;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.page-description {
  color: #666;
}

.header-filters {
  display: flex;
  gap: 1rem;
}

.filter-select {
  padding: 0.5rem 1rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.9rem;
}

.results-container {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: #666;
}

.empty-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 1rem;
  color: #ccc;
}

.results-table-container {
  overflow-x: auto;
}

.results-table {
  width: 100%;
  border-collapse: collapse;
}

.results-table thead {
  background: #f9fafb;
  border-bottom: 2px solid #e0e0e0;
}

.results-table th {
  padding: 1rem;
  text-align: left;
  font-weight: 600;
  font-size: 0.9rem;
  color: #666;
}

.results-table td {
  padding: 1rem;
  border-bottom: 1px solid #e0e0e0;
}

.result-row:hover {
  background: #f9fafb;
}

.config-name {
  color: #666;
  font-size: 0.9rem;
}

.test-type-badge {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  background: #f3f4f6;
  border-radius: 4px;
  font-size: 0.85rem;
  color: #666;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}

.status-passed {
  background: #d1fae5;
  color: #065f46;
}

.status-failed {
  background: #fee2e2;
  color: #991b1b;
}

.status-warning {
  background: #fef3c7;
  color: #92400e;
}

.status-icon {
  width: 16px;
  height: 16px;
}

.findings-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.finding-count {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}

.finding-count.critical {
  background: #fee2e2;
  color: #991b1b;
}

.finding-count.high {
  background: #fed7aa;
  color: #9a3412;
}

.finding-count.medium {
  background: #fef3c7;
  color: #92400e;
}

.finding-count.none {
  color: #10b981;
}

.timestamp {
  color: #666;
  font-size: 0.9rem;
}

.btn-link {
  background: none;
  border: none;
  color: #6366f1;
  cursor: pointer;
  text-decoration: underline;
  font-size: 0.9rem;
}

.btn-link:hover {
  color: #4f46e5;
}

.btn-primary {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  background: #6366f1;
  color: white;
  border-radius: 4px;
  text-decoration: none;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-primary:hover {
  background: #4f46e5;
}
</style>
