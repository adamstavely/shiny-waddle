<template>
  <div class="identity-lifecycle-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Identity Lifecycle Management</h1>
          <p class="page-description">Test identity onboarding, role changes, offboarding, and PAM workflows</p>
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

    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
      </button>
    </div>

    <div class="tab-content">
      <div v-if="activeTab === 'onboarding'" class="lifecycle-section">
        <div class="section-header">
          <div>
            <h2 class="section-title">Identity Onboarding</h2>
            <p class="section-description">Test the complete identity onboarding workflow</p>
          </div>
          <button @click="testOnboarding" class="btn-primary" :disabled="loading">
            <UserPlus v-if="!loading" class="btn-icon" />
            <div v-else class="loading-spinner-small"></div>
            {{ loading ? 'Testing...' : 'Test Onboarding' }}
          </button>
        </div>

        <div v-if="onboardingResult" class="workflow-results">
          <div class="workflow-steps">
            <div
              v-for="(step, idx) in onboardingResult.details?.event?.details?.steps"
              :key="idx"
              class="workflow-step"
              :class="{ completed: step.completed }"
            >
              <div class="step-indicator">
                <CheckCircle2 v-if="step.completed" class="step-icon" />
                <Circle v-else class="step-icon" />
              </div>
              <div class="step-content">
                <h4 class="step-name">{{ step.name }}</h4>
              </div>
            </div>
          </div>
          <div class="result-status" :class="onboardingResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="onboardingResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ onboardingResult.passed ? 'Onboarding Workflow Passed' : 'Onboarding Workflow Failed' }}</span>
          </div>
        </div>
      </div>

      <div v-if="activeTab === 'pam'" class="lifecycle-section">
        <div class="section-header">
          <div>
            <h2 class="section-title">Privileged Access Management</h2>
            <p class="section-description">Test JIT access and break-glass procedures</p>
          </div>
          <div class="header-actions">
            <button @click="testJIT" class="btn-primary" :disabled="loading">
              <Key v-if="!loading" class="btn-icon" />
              <div v-else class="loading-spinner-small"></div>
              {{ loading ? 'Testing...' : 'Test JIT Access' }}
            </button>
            <button @click="testBreakGlass" class="btn-secondary" :disabled="loading">
              <AlertTriangle v-if="!loading" class="btn-icon" />
              <div v-else class="loading-spinner-small"></div>
              {{ loading ? 'Testing...' : 'Test Break-Glass' }}
            </button>
          </div>
        </div>

        <div v-if="pamResult" class="pam-results">
          <div class="result-status" :class="pamResult.passed ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="pamResult.passed" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ pamResult.passed ? 'PAM Test Passed' : 'PAM Test Failed' }}</span>
          </div>
          <div v-if="pamResult.details" class="pam-details">
            <div class="detail-row">
              <span class="detail-label">Request Type:</span>
              <span class="detail-value">{{ pamResult.details.request?.emergency ? 'Break-Glass' : 'JIT Access' }}</span>
            </div>
            <div v-if="pamResult.details.expirationTime" class="detail-row">
              <span class="detail-label">Expiration:</span>
              <span class="detail-value">{{ new Date(pamResult.details.expirationTime).toLocaleString() }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { UserPlus, Key, AlertTriangle, CheckCircle2, XCircle, Circle, Settings, Save } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Identity Lifecycle', to: '/identity-lifecycle' },
];

const router = useRouter();
const loading = ref(false);
const activeTab = ref('onboarding');
const onboardingResult = ref<any>(null);
const pamResult = ref<any>(null);
const selectedConfigId = ref<string>('');
const configurations = ref<any[]>([]);
const currentUser = ref<any>(null);

const hasTestData = computed(() => {
  return currentUser.value !== null;
});

const getConfigName = (id: string) => {
  const config = configurations.value.find(c => c.id === id);
  return config?.name || id;
};

const loadConfigurations = async () => {
  try {
    const response = await axios.get('/api/test-configurations?type=identity-lifecycle');
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
    if (config.user) {
      currentUser.value = config.user;
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
      type: 'identity-lifecycle',
      user: currentUser.value,
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

const tabs = [
  { id: 'onboarding', label: 'Onboarding', icon: UserPlus },
  { id: 'pam', label: 'PAM', icon: Key },
];

const testOnboarding = async () => {
  loading.value = true;
  try {
    const payload: any = {};
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    } else {
      payload.user = currentUser.value || { id: 'test-user', email: 'test@example.com', role: 'viewer', attributes: {} };
    }
    const response = await axios.post('/api/identity-lifecycle/test-onboarding', payload);
    onboardingResult.value = response.data;
  } catch (error) {
    console.error('Error testing onboarding:', error);
  } finally {
    loading.value = false;
  }
};

const testJIT = async () => {
  loading.value = true;
  try {
    const payload: any = {
      request: { userId: 'test-user', resource: 'test-resource', reason: 'Testing', duration: 60 },
    };
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    }
    const response = await axios.post('/api/identity-lifecycle/test-jit-access', payload);
    pamResult.value = response.data;
  } catch (error) {
    console.error('Error testing JIT:', error);
  } finally {
    loading.value = false;
  }
};

const testBreakGlass = async () => {
  loading.value = true;
  try {
    const payload: any = {
      request: { userId: 'test-user', resource: 'test-resource', reason: 'Emergency', duration: 60, emergency: true },
    };
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    }
    const response = await axios.post('/api/identity-lifecycle/test-break-glass', payload);
    pamResult.value = response.data;
  } catch (error) {
    console.error('Error testing break-glass:', error);
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadConfigurations();
});
</script>

<style scoped>
.identity-lifecycle-page {
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

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 32px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  min-height: 400px;
}

.lifecycle-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
  gap: 24px;
  flex-wrap: wrap;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.section-description {
  font-size: 0.9rem;
  color: #a0aec0;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.btn-primary {
  display: flex;
  align-items: center;
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
  white-space: nowrap;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-secondary:disabled {
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

.workflow-results {
  margin-top: 24px;
}

.workflow-steps {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-bottom: 24px;
}

.workflow-step {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.workflow-step.completed {
  border-color: rgba(34, 197, 94, 0.3);
  background: rgba(34, 197, 94, 0.05);
}

.step-indicator {
  flex-shrink: 0;
}

.step-icon {
  width: 24px;
  height: 24px;
}

.workflow-step.completed .step-icon {
  color: #22c55e;
}

.workflow-step:not(.completed) .step-icon {
  color: #718096;
}

.step-content {
  flex: 1;
}

.step-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.result-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px;
  border-radius: 8px;
  font-weight: 600;
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

.pam-results {
  margin-top: 24px;
}

.pam-details {
  margin-top: 16px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
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

.header-actions {
  display: flex;
  gap: 1rem;
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
