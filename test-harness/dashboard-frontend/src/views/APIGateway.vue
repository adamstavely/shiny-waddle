<template>
  <div class="api-gateway-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">API Gateway Security</h1>
          <p class="page-description">Test API gateway policies, rate limiting, and service authentication</p>
        </div>
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
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Server, Shield, Zap, Lock, CheckCircle2, XCircle } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'API Gateway', to: '/api-gateway' },
];

const loading = ref(false);
const policyResult = ref<any>(null);
const rateLimitResult = ref<any>(null);
const authResult = ref<any>(null);

const testPolicy = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/api-gateway/test-gateway-policy', {
      policy: { id: 'test', name: 'Test Policy', endpoint: '/api/test', method: 'GET', rules: [] },
      request: { endpoint: '/api/test', method: 'GET', headers: {}, user: {} },
    });
    policyResult.value = response.data;
  } catch (error) {
    console.error('Error testing policy:', error);
  } finally {
    loading.value = false;
  }
};

const testRateLimit = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/api-gateway/test-rate-limiting', {
      endpoint: '/api/test',
      requests: 150,
    });
    rateLimitResult.value = response.data;
  } catch (error) {
    console.error('Error testing rate limit:', error);
  } finally {
    loading.value = false;
  }
};

const testServiceAuth = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/api-gateway/test-service-auth', {
      source: 'frontend',
      target: 'backend',
    });
    authResult.value = response.data;
  } catch (error) {
    console.error('Error testing service auth:', error);
  } finally {
    loading.value = false;
  }
};
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
</style>
