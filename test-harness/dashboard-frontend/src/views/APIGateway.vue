<template>
  <div class="api-gateway-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">API Gateway Security</h1>
          <p class="page-description">Test API gateway policies, rate limiting, and service authentication</p>
        </div>
        <div class="header-actions">
          <button @click="navigateToConfig" class="btn-secondary">
            <Settings class="btn-icon" />
            Configure
          </button>
        </div>
      </div>
    </div>

    <!-- Configuration Selector -->
    <div class="config-selector">
      <div class="selector-group">
        <label>Use Configuration:</label>
        <select v-model="selectedConfigId" @change="loadConfiguration">
          <option value="">None (Use Defaults)</option>
          <option v-for="config in configurations" :key="config.id" :value="config.id">
            {{ config.name }}
          </option>
        </select>
      </div>
      <div class="selector-actions">
        <button @click="saveCurrentAsConfig" class="btn-secondary" :disabled="!hasTestData">
          <Save class="btn-icon" />
          Save as Configuration
        </button>
      </div>
      <div v-if="selectedConfigId" class="active-config">
        <CheckCircle2 class="icon" />
        <span>Using: {{ getConfigName(selectedConfigId) }}</span>
      </div>
    </div>

    <div class="test-sections">
      <div class="test-card">
        <div class="card-header">
          <Server class="card-icon" />
          <h2 class="card-title">Gateway Policy</h2>
        </div>
        <p class="card-description">Test API gateway access policies and rules</p>
        <button @click="testPolicy" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Policy' }}
        </button>
        <div v-if="policyResult" class="results">
          <div class="result-status" :class="policyResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="policyResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ policyResult.passed ? 'Policy Test Passed' : 'Policy Test Failed' }}</span>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <Zap class="card-icon" />
          <h2 class="card-title">Rate Limiting</h2>
        </div>
        <p class="card-description">Test rate limiting enforcement and thresholds</p>
        <button @click="testRateLimit" class="btn-primary" :disabled="loading">
          <Zap v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Rate Limit' }}
        </button>
        <div v-if="rateLimitResult" class="results">
          <div class="result-item">
            <span class="result-label">Blocked:</span>
            <span class="result-value" :class="rateLimitResult.blocked ? 'error' : 'success'">
              {{ rateLimitResult.blocked ? 'Yes' : 'No' }}
            </span>
          </div>
          <div class="result-item">
            <span class="result-label">Requests:</span>
            <span class="result-value">{{ rateLimitResult.actualRequests }}/{{ rateLimitResult.limit }}</span>
          </div>
          <div class="result-item">
            <span class="result-label">Time Window:</span>
            <span class="result-value">{{ rateLimitResult.timeWindow }}s</span>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <Lock class="card-icon" />
          <h2 class="card-title">Service Auth</h2>
        </div>
        <p class="card-description">Test service-to-service authentication</p>
        <button @click="testServiceAuth" class="btn-primary" :disabled="loading">
          <Lock v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Service Auth' }}
        </button>
        <div v-if="authResult" class="results">
          <div class="result-status" :class="authResult.authenticated ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="authResult.authenticated" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ authResult.authenticated ? 'Authenticated' : 'Not Authenticated' }}</span>
          </div>
          <div v-if="authResult.authMethod" class="auth-details">
            <div class="detail-row">
              <span class="detail-label">Method:</span>
              <span class="detail-value">{{ authResult.authMethod.toUpperCase() }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <TestResultsModal
      :show="showResultsModal"
      :results="testResults"
      :error="testError"
      @close="closeResultsModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Server, Shield, Zap, Lock, CheckCircle2, XCircle, Settings, Save } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestResultsModal from '../components/configurations/TestResultsModal.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'API Gateway', to: '/api-gateway' },
];

const router = useRouter();
const loading = ref(false);
const policyResult = ref<any>(null);
const rateLimitResult = ref<any>(null);
const authResult = ref<any>(null);
const selectedConfigId = ref<string>('');
const configurations = ref<any[]>([]);
const currentPolicies = ref<any[]>([]);
const testResults = ref<any>(null);
const testError = ref<string | null>(null);
const showResultsModal = ref(false);

const hasTestData = computed(() => {
  return currentPolicies.value.length > 0;
});

const getConfigName = (id: string) => {
  const config = configurations.value.find(c => c.id === id);
  return config?.name || id;
};

const loadConfigurations = async () => {
  try {
    const response = await axios.get('/api/test-configurations?type=api-gateway');
    configurations.value = response.data;
  } catch (error) {
    console.error('Error loading configurations:', error);
  }
};

const loadConfiguration = async () => {
  if (!selectedConfigId.value) {
    return;
  }
  try {
    const response = await axios.get(`/api/test-configurations/${selectedConfigId.value}`);
    const config = response.data;
    if (config.gatewayPolicies) {
      currentPolicies.value = config.gatewayPolicies;
    }
  } catch (error) {
    console.error('Error loading configuration:', error);
  }
};

const saveCurrentAsConfig = async () => {
  const name = prompt('Enter configuration name:');
  if (!name) return;
  try {
    await axios.post('/api/test-configurations', {
      name,
      type: 'api-gateway',
      gatewayPolicies: currentPolicies.value,
    });
    await loadConfigurations();
    alert('Configuration saved successfully!');
  } catch (error: any) {
    alert('Error saving configuration: ' + (error.response?.data?.message || error.message));
  }
};

const navigateToConfig = () => {
  router.push('/test-configurations');
};

const testPolicy = async () => {
  loading.value = true;
  testError.value = null;
  testResults.value = null;
  try {
    const payload: any = {
      policy: { id: 'test', name: 'Test Policy', endpoint: '/api/test', method: 'GET', rules: [] },
      request: { endpoint: '/api/test', method: 'GET', headers: {}, user: {} },
    };
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    }
    const response = await axios.post('/api/api-gateway/test-gateway-policy', payload);
    policyResult.value = response.data;
    testResults.value = response.data;
    showResultsModal.value = true;
  } catch (error: any) {
    testError.value = error.response?.data?.message || 'Failed to test gateway policy';
    showResultsModal.value = true;
    console.error('Error testing policy:', error);
  } finally {
    loading.value = false;
  }
};

const testRateLimit = async () => {
  loading.value = true;
  testError.value = null;
  testResults.value = null;
  try {
    const payload: any = {
      endpoint: '/api/test',
      requests: 150,
    };
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    }
    const response = await axios.post('/api/api-gateway/test-rate-limiting', payload);
    rateLimitResult.value = response.data;
    testResults.value = response.data;
    showResultsModal.value = true;
  } catch (error: any) {
    testError.value = error.response?.data?.message || 'Failed to test rate limiting';
    showResultsModal.value = true;
    console.error('Error testing rate limit:', error);
  } finally {
    loading.value = false;
  }
};

const testServiceAuth = async () => {
  loading.value = true;
  testError.value = null;
  testResults.value = null;
  try {
    const payload: any = {
      source: 'frontend',
      target: 'backend',
    };
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    }
    const response = await axios.post('/api/api-gateway/test-service-auth', payload);
    authResult.value = response.data;
    testResults.value = response.data;
    showResultsModal.value = true;
  } catch (error: any) {
    testError.value = error.response?.data?.message || 'Failed to test service auth';
    showResultsModal.value = true;
    console.error('Error testing service auth:', error);
  } finally {
    loading.value = false;
  }
};

const closeResultsModal = () => {
  showResultsModal.value = false;
  testResults.value = null;
  testError.value = null;
};

onMounted(() => {
  loadConfigurations();
});
</script>

<style scoped>
.api-gateway-page {
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

.result-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.result-item:last-child {
  border-bottom: none;
}

.result-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.result-value {
  font-size: 1rem;
  color: #ffffff;
  font-weight: 600;
}

.result-value.success {
  color: #22c55e;
}

.result-value.error {
  color: #fc8181;
}

.auth-details {
  margin-top: 12px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
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

.header-actions {
  display: flex;
  gap: 1rem;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-secondary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.config-selector {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.selector-group {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.selector-group label {
  color: #a0aec0;
  font-weight: 500;
  font-size: 0.9rem;
}

.selector-group select {
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.9rem;
  min-width: 200px;
}

.selector-group select:focus {
  outline: none;
  border-color: #4facfe;
}

.selector-actions {
  margin-left: auto;
}

.active-config {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 8px 12px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 6px;
  color: #22c55e;
  font-size: 0.875rem;
}

.active-config .icon {
  width: 16px;
  height: 16px;
}
</style>
