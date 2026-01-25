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
        <button @click="testProvider(provider.id)" class="btn-primary" :disabled="testingProviders[provider.id]">
          <Shield v-if="!testingProviders[provider.id]" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ testingProviders[provider.id] ? 'Testing...' : 'Test Integration' }}
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
import { useApiData } from '../composables/useApiData';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Identity Providers', to: '/identity-providers' },
];

const testResults = ref<Record<string, any>>({});

const providers = [
  { id: 'ad', name: 'Active Directory', description: 'Test AD group membership and policies', icon: Users },
  { id: 'okta', name: 'Okta', description: 'Test Okta policy synchronization', icon: Shield },
  { id: 'auth0', name: 'Auth0', description: 'Test Auth0 policy synchronization', icon: Key },
  { id: 'azure-ad', name: 'Azure AD', description: 'Test Azure AD conditional access policies', icon: Cloud },
  { id: 'gcp', name: 'GCP IAM', description: 'Test GCP IAM bindings and policies', icon: Cloud },
];

const testProvider = async (providerId: string) => {
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

  const { loading, load } = useApiData(
    async () => {
      const response = await axios.post(endpoint, payload);
      testResults.value[providerId] = response.data;
      return response.data;
    },
    {
      errorMessage: `Failed to test ${providerId} integration`,
    }
  );

  await load();
};
</script>

<style scoped>
.identity-providers-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
  flex-wrap: wrap;
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.providers-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--spacing-lg);
}

.provider-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.provider-card:hover {
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.card-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.card-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.card-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.card-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xl);
  line-height: 1.5;
}

.btn-primary {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  width: 100%;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: var(--border-width-medium) solid rgba(255, 255, 255, 0.3);
  border-top-color: var(--color-text-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.test-results {
  margin-top: var(--spacing-xl);
  padding-top: var(--spacing-xl);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.result-status {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-semibold);
  margin-bottom: var(--spacing-sm);
}

.status-success {
  background: var(--color-success-bg);
  border: var(--border-width-thin) solid var(--color-success);
  color: var(--color-success);
}

.status-error {
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  color: var(--color-error);
}

.status-icon {
  width: 20px;
  height: 20px;
}

.result-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.check-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.check-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.check-icon.success {
  color: var(--color-success);
}

.check-icon.error {
  color: var(--color-error);
}
</style>
