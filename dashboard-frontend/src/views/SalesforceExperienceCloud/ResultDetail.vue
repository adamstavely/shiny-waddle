<template>
  <div class="result-detail-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div v-if="loading" class="loading">Loading result...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error && result" class="result-detail-content">
      <div class="page-header">
        <div class="header-content">
          <div>
            <h1 class="page-title">{{ result.testName }}</h1>
            <p class="page-description">{{ getConfigName(result.configId) }} • {{ formatDate(result.timestamp) }}</p>
          </div>
          <div class="header-badge">
            <span class="status-badge" :class="getStatusClass(result.status)">
              <CheckCircle2 v-if="result.status === 'passed'" class="status-icon" />
              <XCircle v-else-if="result.status === 'failed'" class="status-icon" />
              <AlertCircle v-else class="status-icon" />
              {{ result.status.toUpperCase() }}
            </span>
          </div>
        </div>
      </div>

      <div class="result-details-grid">
        <div class="detail-section">
          <h2 class="section-title">Test Information</h2>
          <div class="detail-list">
            <div class="detail-item">
              <span class="detail-label">Test Name:</span>
              <span class="detail-value">{{ result.testName }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Test Type:</span>
              <span class="detail-value">{{ result.testType }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Configuration:</span>
              <span class="detail-value">{{ getConfigName(result.configId) }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Status:</span>
              <span class="detail-value">{{ result.status }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Timestamp:</span>
              <span class="detail-value">{{ formatDate(result.timestamp) }}</span>
            </div>
            <div v-if="result.error" class="detail-item">
              <span class="detail-label">Error:</span>
              <span class="detail-value error-text">{{ result.error }}</span>
            </div>
          </div>
        </div>

        <div v-if="result.summary" class="detail-section">
          <h2 class="section-title">Summary</h2>
          <div class="summary-stats">
            <div class="stat-card">
              <div class="stat-value">{{ result.summary.totalFindings }}</div>
              <div class="stat-label">Total Findings</div>
            </div>
            <div v-if="result.summary.criticalCount > 0" class="stat-card critical">
              <div class="stat-value">{{ result.summary.criticalCount }}</div>
              <div class="stat-label">Critical</div>
            </div>
            <div v-if="result.summary.highCount > 0" class="stat-card high">
              <div class="stat-value">{{ result.summary.highCount }}</div>
              <div class="stat-label">High</div>
            </div>
            <div v-if="result.summary.mediumCount > 0" class="stat-card medium">
              <div class="stat-value">{{ result.summary.mediumCount }}</div>
              <div class="stat-label">Medium</div>
            </div>
            <div v-if="result.summary.lowCount && result.summary.lowCount > 0" class="stat-card low">
              <div class="stat-value">{{ result.summary.lowCount }}</div>
              <div class="stat-label">Low</div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="result.findings && result.findings.length > 0" class="findings-section">
        <h2 class="section-title">Findings</h2>
        <div class="findings-list">
          <div
            v-for="(finding, index) in result.findings"
            :key="index"
            class="finding-card"
            :class="`severity-${finding.severity}`"
          >
            <div class="finding-header">
              <span class="severity-badge" :class="`severity-${finding.severity}`">
                {{ finding.severity.toUpperCase() }}
              </span>
              <span class="finding-type">{{ finding.type }}</span>
            </div>
            <div class="finding-description">{{ finding.description }}</div>
            <div v-if="finding.objects && finding.objects.length > 0" class="finding-details">
              <strong>Objects:</strong> {{ finding.objects.join(', ') }}
            </div>
            <div v-if="finding.urls && finding.urls.length > 0" class="finding-details">
              <strong>URLs:</strong>
              <ul>
                <li v-for="url in finding.urls" :key="url">{{ url }}</li>
              </ul>
            </div>
            <div v-if="finding.recordCount !== undefined" class="finding-details">
              <strong>Record Count:</strong> {{ finding.recordCount }}
            </div>
            <div v-if="finding.details" class="finding-details">
              <pre>{{ JSON.stringify(finding.details, null, 2) }}</pre>
            </div>
          </div>
        </div>
      </div>

      <div v-if="result.accessibleRecords && result.accessibleRecords.length > 0" class="records-section">
        <h2 class="section-title">Accessible Records</h2>
        <div class="records-list">
          <div class="records-count">
            Total: {{ result.recordCount || result.accessibleRecords.length }} records
          </div>
          <div class="records-table-container">
            <table class="records-table">
              <thead>
                <tr>
                  <th v-for="key in getRecordKeys(result.accessibleRecords)" :key="key">
                    {{ key }}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(record, index) in result.accessibleRecords.slice(0, 100)" :key="index">
                  <td v-for="key in getRecordKeys(result.accessibleRecords)" :key="key">
                    {{ formatRecordValue(record[key]) }}
                  </td>
                </tr>
              </tbody>
            </table>
            <div v-if="result.accessibleRecords.length > 100" class="records-truncated">
              Showing first 100 of {{ result.accessibleRecords.length }} records
            </div>
          </div>
        </div>
      </div>

      <div v-if="result.details" class="details-section">
        <h2 class="section-title">Additional Details</h2>
        <pre class="details-json">{{ JSON.stringify(result.details, null, 2) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { CheckCircle2, XCircle, AlertCircle } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import { useSalesforceExperienceCloud } from '../../composables/useSalesforceExperienceCloud';
import type { SalesforceExperienceCloudTestResultEntity, SalesforceExperienceCloudConfigEntity } from '../../types/salesforce-experience-cloud';

const route = useRoute();
const router = useRouter();
const { loading, error, getResult, getConfigs } = useSalesforceExperienceCloud();

const result = ref<SalesforceExperienceCloudTestResultEntity | null>(null);
const configs = ref<SalesforceExperienceCloudConfigEntity[]>([]);
const resultId = route.params.id as string;

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Salesforce Experience Cloud', to: '/salesforce-experience-cloud' },
  { label: 'Results', to: '/salesforce-experience-cloud/results' },
  { label: result.value?.testName || 'Result', to: '' },
]);

const loadResult = async () => {
  try {
    result.value = await getResult(resultId);
  } catch (err) {
    console.error('Failed to load result:', err);
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

const getStatusClass = (status: string) => {
  return {
    'status-passed': status === 'passed',
    'status-failed': status === 'failed',
    'status-warning': status === 'warning',
  };
};

const getRecordKeys = (records: any[]) => {
  if (!records || records.length === 0) return [];
  const allKeys = new Set<string>();
  records.forEach(record => {
    Object.keys(record).forEach(key => allKeys.add(key));
  });
  return Array.from(allKeys);
};

const formatRecordValue = (value: any) => {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

const formatDate = (date: Date | string) => {
  return new Date(date).toLocaleString();
};

onMounted(() => {
  loadConfigs();
  loadResult();
});
</script>

<style scoped>
.result-detail-page {
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

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.5rem 1rem;
  border-radius: 4px;
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
  width: 18px;
  height: 18px;
}

.result-details-grid {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 2rem;
  margin-bottom: 2rem;
}

.detail-section {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin-bottom: 1rem;
}

.detail-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.detail-item {
  display: flex;
  gap: 0.5rem;
}

.detail-label {
  font-weight: 500;
  color: #666;
  min-width: 150px;
}

.detail-value {
  color: #333;
  word-break: break-all;
}

.error-text {
  color: #ef4444;
}

.summary-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 1rem;
}

.stat-card {
  text-align: center;
  padding: 1rem;
  background: #f9fafb;
  border-radius: 8px;
}

.stat-card.critical {
  background: #fee2e2;
}

.stat-card.high {
  background: #fed7aa;
}

.stat-card.medium {
  background: #fef3c7;
}

.stat-card.low {
  background: #e0e7ff;
}

.stat-value {
  font-size: 2rem;
  font-weight: 600;
  color: #333;
}

.stat-label {
  font-size: 0.9rem;
  color: #666;
  margin-top: 0.5rem;
}

.findings-section,
.records-section,
.details-section {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 2rem;
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.finding-card {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1rem;
}

.finding-card.severity-critical {
  border-left: 4px solid #ef4444;
}

.finding-card.severity-high {
  border-left: 4px solid #f59e0b;
}

.finding-card.severity-medium {
  border-left: 4px solid #fbbf24;
}

.finding-card.severity-low {
  border-left: 4px solid #6366f1;
}

.finding-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.severity-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.severity-critical {
  background: #fee2e2;
  color: #991b1b;
}

.severity-high {
  background: #fed7aa;
  color: #9a3412;
}

.severity-medium {
  background: #fef3c7;
  color: #92400e;
}

.severity-low {
  background: #e0e7ff;
  color: #3730a3;
}

.finding-type {
  color: #666;
  font-size: 0.9rem;
}

.finding-description {
  margin-bottom: 0.5rem;
  color: #333;
}

.finding-details {
  margin-top: 0.5rem;
  font-size: 0.9rem;
  color: #666;
}

.finding-details ul {
  margin: 0.25rem 0;
  padding-left: 1.5rem;
}

.finding-details pre {
  background: #f9fafb;
  padding: 0.5rem;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.85rem;
}

.records-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.records-count {
  font-weight: 500;
  color: #666;
}

.records-table-container {
  overflow-x: auto;
}

.records-table {
  width: 100%;
  border-collapse: collapse;
}

.records-table th,
.records-table td {
  padding: 0.5rem;
  border: 1px solid #e0e0e0;
  text-align: left;
  font-size: 0.9rem;
}

.records-table thead {
  background: #f9fafb;
}

.records-truncated {
  margin-top: 0.5rem;
  color: #666;
  font-size: 0.9rem;
  font-style: italic;
}

.details-json {
  background: #f9fafb;
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.85rem;
  max-height: 500px;
  overflow-y: auto;
}
</style>
