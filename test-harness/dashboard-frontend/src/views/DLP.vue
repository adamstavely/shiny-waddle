<template>
  <div class="dlp-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Data Loss Prevention</h1>
          <p class="page-description">Test data exfiltration detection, API response validation, and bulk export controls</p>
        </div>
      </div>
    </div>

    <div class="test-sections">
      <div class="test-card">
        <div class="card-header">
          <FileX class="card-icon" />
          <h2 class="card-title">Exfiltration Detection</h2>
        </div>
        <p class="card-description">Detect unauthorized data exfiltration attempts</p>
        <button @click="testExfiltration" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Exfiltration' }}
        </button>
        <div v-if="exfiltrationResult" class="results">
          <div class="result-status" :class="exfiltrationResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="exfiltrationResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ exfiltrationResult.passed ? 'No Exfiltration Detected' : 'Exfiltration Detected' }}</span>
          </div>
          <div v-if="exfiltrationResult.details?.exfiltrationTest?.pattern" class="pattern-detected">
            <AlertTriangle class="pattern-icon" />
            <span>Pattern: {{ exfiltrationResult.details.exfiltrationTest.pattern.name }}</span>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <Shield class="card-icon" />
          <h2 class="card-title">API Response Validation</h2>
        </div>
        <p class="card-description">Validate API responses don't leak sensitive data</p>
        <button @click="validateAPI" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Validating...' : 'Validate Response' }}
        </button>
        <div v-if="apiValidationResult" class="results">
          <div class="result-status" :class="apiValidationResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="apiValidationResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ apiValidationResult.passed ? 'Response Valid' : 'Response Invalid' }}</span>
          </div>
          <div v-if="apiValidationResult.details?.violations?.length > 0" class="violations-list">
            <p class="violations-title">Violations:</p>
            <ul>
              <li v-for="(violation, idx) in apiValidationResult.details.violations" :key="idx">{{ violation }}</li>
            </ul>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <FileX class="card-icon" />
          <h2 class="card-title">Bulk Export Controls</h2>
        </div>
        <p class="card-description">Test bulk export restrictions and limits</p>
        <button @click="testBulkExport" class="btn-primary" :disabled="loading">
          <FileX v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Export' }}
        </button>
        <div v-if="bulkExportResult" class="results">
          <div class="result-status" :class="bulkExportResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="bulkExportResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ bulkExportResult.passed ? 'Export Allowed' : 'Export Blocked' }}</span>
          </div>
          <div v-if="bulkExportResult.details?.bulkExportTest" class="export-details">
            <div class="detail-row">
              <span class="detail-label">Record Count:</span>
              <span class="detail-value">{{ bulkExportResult.details.bulkExportTest.recordCount }}</span>
            </div>
            <div v-if="bulkExportResult.details.bulkExportTest.reason" class="detail-row">
              <span class="detail-label">Reason:</span>
              <span class="detail-value error">{{ bulkExportResult.details.bulkExportTest.reason }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { FileX, Shield, CheckCircle2, XCircle, AlertTriangle } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'DLP', to: '/dlp' },
];

const loading = ref(false);
const exfiltrationResult = ref<any>(null);
const apiValidationResult = ref<any>(null);
const bulkExportResult = ref<any>(null);

const testExfiltration = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/dlp/test-exfiltration', {
      user: { id: 'test', email: 'test@example.com', role: 'viewer', attributes: {} },
      dataOperation: { type: 'export', resource: { id: 'test', type: 'data', attributes: {} }, data: {} },
    });
    exfiltrationResult.value = response.data;
  } catch (error) {
    console.error('Error testing exfiltration:', error);
  } finally {
    loading.value = false;
  }
};

const validateAPI = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/dlp/validate-api-response', {
      apiResponse: {},
      allowedFields: ['id', 'name'],
      piiFields: ['email', 'ssn'],
    });
    apiValidationResult.value = response.data;
  } catch (error) {
    console.error('Error validating API:', error);
  } finally {
    loading.value = false;
  }
};

const testBulkExport = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/dlp/test-bulk-export', {
      user: { id: 'test', email: 'test@example.com', role: 'viewer', attributes: {} },
      exportRequest: { type: 'csv', recordCount: 5000 },
    });
    bulkExportResult.value = response.data;
  } catch (error) {
    console.error('Error testing bulk export:', error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.dlp-page {
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
  flex-wrap: wrap;
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

.test-sections {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 24px;
}

.test-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  transition: all 0.3s;
}

.test-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.card-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.card-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 20px;
  line-height: 1.5;
}

.btn-primary {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  width: 100%;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: #ffffff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.results {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.result-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  border-radius: 8px;
  font-weight: 600;
  margin-bottom: 12px;
}

.status-success {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.status-error {
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.status-icon {
  width: 20px;
  height: 20px;
}

.pattern-detected {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
  color: #fbbf24;
  font-size: 0.875rem;
}

.pattern-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.violations-list {
  margin-top: 12px;
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
}

.violations-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #fc8181;
  margin-bottom: 8px;
}

.violations-list ul {
  margin: 0;
  padding-left: 20px;
  color: #fc8181;
  font-size: 0.875rem;
}

.violations-list li {
  margin-bottom: 4px;
}

.export-details {
  margin-top: 12px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-row:last-child {
  border-bottom: none;
}

.detail-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.detail-value {
  font-size: 0.9rem;
  color: #ffffff;
  font-weight: 600;
}

.detail-value.error {
  color: #fc8181;
}
</style>
