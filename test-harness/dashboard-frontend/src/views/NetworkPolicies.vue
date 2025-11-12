<template>
  <div class="network-policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Network Micro-Segmentation</h1>
          <p class="page-description">Test firewall rules, network segmentation, and service mesh policies</p>
        </div>
      </div>
    </div>

    <div class="test-sections">
      <div class="test-card">
        <div class="card-header">
          <Network class="card-icon" />
          <h2 class="card-title">Firewall Rules</h2>
        </div>
        <p class="card-description">Test firewall rule configuration and enforcement</p>
        <button @click="testFirewall" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Firewall Rules' }}
        </button>
        <div v-if="firewallResults.length > 0" class="results">
          <div class="result-summary">
            <span class="summary-label">Tests Run:</span>
            <span class="summary-value">{{ firewallResults.length }}</span>
          </div>
          <div class="result-summary">
            <span class="summary-label">Passed:</span>
            <span class="summary-value success">{{ firewallResults.filter(r => r.passed).length }}</span>
          </div>
          <div class="result-summary">
            <span class="summary-label">Failed:</span>
            <span class="summary-value error">{{ firewallResults.filter(r => !r.passed).length }}</span>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <Network class="card-icon" />
          <h2 class="card-title">Service-to-Service</h2>
        </div>
        <p class="card-description">Test service-to-service traffic policies</p>
        <button @click="testServiceToService" class="btn-primary" :disabled="loading">
          <Network v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Service Traffic' }}
        </button>
        <div v-if="serviceResult" class="results">
          <div class="result-status" :class="serviceResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="serviceResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ serviceResult.passed ? 'Traffic Allowed' : 'Traffic Blocked' }}</span>
          </div>
          <div v-if="serviceResult.details" class="service-details">
            <div class="detail-row">
              <span class="detail-label">Source:</span>
              <span class="detail-value">{{ serviceResult.details.source }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Target:</span>
              <span class="detail-value">{{ serviceResult.details.target }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <Network class="card-icon" />
          <h2 class="card-title">Network Segmentation</h2>
        </div>
        <p class="card-description">Validate network segmentation policies</p>
        <button @click="testSegmentation" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Segmentation' }}
        </button>
        <div v-if="segmentationResults.length > 0" class="results">
          <div class="result-summary">
            <span class="summary-label">Segments Tested:</span>
            <span class="summary-value">{{ segmentationResults.length }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Network, Shield, CheckCircle2, XCircle } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Network Policies', to: '/network-policies' },
];

const loading = ref(false);
const firewallResults = ref<any[]>([]);
const serviceResult = ref<any>(null);
const segmentationResults = ref<any[]>([]);

const testFirewall = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/network-policy/test-firewall-rules', {
      rules: [],
    });
    firewallResults.value = response.data;
  } catch (error) {
    console.error('Error testing firewall:', error);
  } finally {
    loading.value = false;
  }
};

const testServiceToService = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/network-policy/test-service-to-service', {
      source: 'frontend',
      target: 'backend',
    });
    serviceResult.value = response.data;
  } catch (error) {
    console.error('Error testing service-to-service:', error);
  } finally {
    loading.value = false;
  }
};

const testSegmentation = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/network-policy/validate-segmentation', {
      segments: [],
    });
    segmentationResults.value = response.data;
  } catch (error) {
    console.error('Error testing segmentation:', error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.network-policies-page {
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

.result-summary {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.result-summary:last-child {
  border-bottom: none;
}

.summary-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.summary-value {
  font-size: 1rem;
  color: #ffffff;
  font-weight: 600;
}

.summary-value.success {
  color: #22c55e;
}

.summary-value.error {
  color: #fc8181;
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

.service-details {
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
</style>
