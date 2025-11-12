<template>
  <div class="identity-providers-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Identity Provider Integration</h1>
          <p class="page-description">Test integration with AD, Okta, Auth0, Azure AD, and GCP IAM</p>
        </div>
      </div>
    </div>

    <div class="providers-grid">
      <div v-for="provider in providers" :key="provider.id" class="provider-card">
        <div class="card-header">
          <component :is="provider.icon" class="card-icon" />
          <h3 class="card-title">{{ provider.name }}</h3>
        </div>
        <p class="card-description">{{ provider.description }}</p>
        <button @click="testProvider(provider.id)" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Integration' }}
        </button>
        <div v-if="testResults[provider.id]" class="test-results">
          <div class="result-status" :class="testResults[provider.id].passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="testResults[provider.id].passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ testResults[provider.id].passed ? 'Integration Verified' : 'Integration Failed' }}</span>
          </div>
          <div v-if="testResults[provider.id].details" class="result-details">
            <div v-for="(check, idx) in testResults[provider.id].details.checks" :key="idx" class="check-item">
              <CheckCircle2 v-if="check.passed" class="check-icon success" />
              <XCircle v-else class="check-icon error" />
              <span>{{ check.name }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Shield, CheckCircle2, XCircle, Users, Key, Cloud } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Identity Providers', to: '/identity-providers' },
];

const loading = ref(false);
const testResults = ref<Record<string, any>>({});

const providers = [
  { id: 'ad', name: 'Active Directory', description: 'Test AD group membership and policies', icon: Users },
  { id: 'okta', name: 'Okta', description: 'Test Okta policy synchronization', icon: Shield },
  { id: 'auth0', name: 'Auth0', description: 'Test Auth0 policy synchronization', icon: Key },
  { id: 'azure-ad', name: 'Azure AD', description: 'Test Azure AD conditional access policies', icon: Cloud },
  { id: 'gcp', name: 'GCP IAM', description: 'Test GCP IAM bindings and policies', icon: Cloud },
];

const testProvider = async (providerId: string) => {
  loading.value = true;
  try {
    let endpoint = '';
    let payload: any = {};

    switch (providerId) {
      case 'ad':
        endpoint = '/api/identity-providers/test-ad-group';
        payload = { user: { id: 'test', email: 'test@example.com', role: 'viewer', attributes: {} }, group: 'test-group' };
        break;
      case 'okta':
        endpoint = '/api/identity-providers/test-okta-policy';
        payload = { policy: { policyId: 'test', policyName: 'Test Policy', synchronized: true, lastSync: new Date(), violations: [] } };
        break;
      case 'auth0':
        endpoint = '/api/identity-providers/test-auth0-policy';
        payload = { policy: {} };
        break;
      case 'azure-ad':
        endpoint = '/api/identity-providers/test-azure-ad-conditional-access';
        payload = { policy: { id: 'test', name: 'Test Policy', conditions: {}, grantControls: {} } };
        break;
      case 'gcp':
        endpoint = '/api/identity-providers/test-gcp-iam-binding';
        payload = { binding: { resource: 'test', role: 'test-role', members: [] } };
        break;
    }

    const response = await axios.post(endpoint, payload);
    testResults.value[providerId] = response.data;
  } catch (error) {
    console.error(`Error testing ${providerId}:`, error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.identity-providers-page {
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

.providers-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
}

.provider-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  transition: all 0.3s;
}

.provider-card:hover {
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

.test-results {
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

.result-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.check-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.check-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.check-icon.success {
  color: #22c55e;
}

.check-icon.error {
  color: #fc8181;
}
</style>
