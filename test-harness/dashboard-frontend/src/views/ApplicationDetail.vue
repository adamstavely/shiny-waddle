<template>
  <div class="application-detail-page">
    <div v-if="loading" class="loading">Loading application details...</div>
    <div v-if="error" class="error">{{ error }}</div>
    
    <div v-if="!loading && !error && application" class="detail-content">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <h1 class="page-title">{{ application.name }}</h1>
            <p class="page-meta">
              {{ application.type.toUpperCase() }} • {{ application.status }}
            </p>
            <p v-if="application.description" class="page-description">{{ application.description }}</p>
          </div>
          <div class="header-actions">
            <button @click="refreshData" class="action-btn" :disabled="isRefreshing">
              <RefreshCw class="action-icon" :class="{ spinning: isRefreshing }" />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <!-- Application Info Section -->
      <div class="content-section">
        <h2 class="section-title">
          <Info class="section-icon" />
          Application Information
        </h2>
        <div class="info-grid">
          <div class="info-item">
            <span class="info-label">ID</span>
            <span class="info-value">{{ application.id }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Team</span>
            <span class="info-value">{{ application.team || 'Unassigned' }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Base URL</span>
            <span class="info-value">{{ application.baseUrl || 'N/A' }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Registered</span>
            <span class="info-value">{{ formatDate(application.registeredAt) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Last Test</span>
            <span class="info-value">{{ application.lastTestAt ? formatDate(application.lastTestAt) : 'Never' }}</span>
          </div>
        </div>
      </div>

      <!-- Test Configuration Management Section -->
      <div class="content-section">
        <div class="section-header">
          <h2 class="section-title">
            <TestTube class="section-icon" />
            Test Configuration Management
          </h2>
          <button @click="showBulkTestConfigPanel = !showBulkTestConfigPanel" class="btn-secondary">
            <Settings class="btn-icon" />
            Bulk Toggle
          </button>
        </div>
        
        <BulkTogglePanel
          v-if="showBulkTestConfigPanel"
          :items="testConfigStatuses.map(c => ({ id: c.configId, name: c.name, enabled: c.enabled }))"
          :loading="loading"
          @bulk-toggle="handleBulkToggleTestConfigs"
          @cancel="showBulkTestConfigPanel = false"
        />

        <div v-if="testConfigStatuses.length === 0" class="empty-state">
          <p>No test configurations assigned to this application</p>
        </div>
        
        <div v-else class="toggles-list">
          <TestConfigToggle
            v-for="config in testConfigStatuses"
            :key="config.configId"
            :application-id="application.id"
            :config="config"
            @updated="loadTestConfigStatuses"
          />
        </div>
      </div>

      <!-- Test Assignment Management Section -->
      <div class="content-section">
        <AssignmentManager
          :application-id="application.id"
          @updated="refreshData"
        />
      </div>

      <!-- Validator Management Section -->
      <div class="content-section">
        <div class="section-header">
          <h2 class="section-title">
            <Shield class="section-icon" />
            Validator Management
          </h2>
          <button @click="showBulkValidatorPanel = !showBulkValidatorPanel" class="btn-secondary">
            <Settings class="btn-icon" />
            Bulk Toggle
          </button>
        </div>
        
        <BulkTogglePanel
          v-if="showBulkValidatorPanel"
          :items="validatorStatuses.map(v => ({ id: v.validatorId, name: v.name, enabled: v.enabled }))"
          :loading="loading"
          @bulk-toggle="handleBulkToggleValidators"
          @cancel="showBulkValidatorPanel = false"
        />

        <div v-if="validatorStatuses.length === 0" class="empty-state">
          <p>No validators available</p>
        </div>
        
        <div v-else class="toggles-list">
          <ValidatorToggle
            v-for="validator in validatorStatuses"
            :key="validator.validatorId"
            :application-id="application.id"
            :validator="validator"
            @updated="loadValidatorStatuses"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import axios from 'axios';
import {
  RefreshCw,
  TestTube,
  Shield,
  Info,
  Settings,
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestConfigToggle from '../components/TestConfigToggle.vue';
import ValidatorToggle from '../components/ValidatorToggle.vue';
import BulkTogglePanel from '../components/BulkTogglePanel.vue';
import AssignmentManager from '../components/AssignmentManager.vue';

const route = useRoute();
const router = useRouter();

const applicationId = computed(() => route.params.id as string);

const loading = ref(true);
const error = ref<string | null>(null);
const isRefreshing = ref(false);
const application = ref<any>(null);
const testConfigStatuses = ref<any[]>([]);
const validatorStatuses = ref<any[]>([]);
const showBulkTestConfigPanel = ref(false);
const showBulkValidatorPanel = ref(false);

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: application.value?.name || 'Application' }
]);

const loadApplication = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get(`/api/applications/${applicationId.value}`);
    application.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load application';
    console.error('Error loading application:', err);
  } finally {
    loading.value = false;
  }
};

const loadTestConfigStatuses = async () => {
  try {
    const response = await axios.get(`/api/applications/${applicationId.value}/test-configurations/status`);
    testConfigStatuses.value = response.data;
  } catch (err: any) {
    console.error('Error loading test configuration statuses:', err);
  }
};

const loadValidatorStatuses = async () => {
  try {
    const response = await axios.get(`/api/applications/${applicationId.value}/validators/status`);
    validatorStatuses.value = response.data;
  } catch (err: any) {
    console.error('Error loading validator statuses:', err);
  }
};

const handleBulkToggleTestConfigs = async (items: Array<{ id: string; enabled: boolean; reason?: string }>) => {
  try {
    loading.value = true;
    await axios.patch(
      `/api/applications/${applicationId.value}/test-configurations/bulk-toggle`,
      { items }
    );
    await loadTestConfigStatuses();
    showBulkTestConfigPanel.value = false;
  } catch (err: any) {
    console.error('Error bulk toggling test configs:', err);
    alert(err.response?.data?.message || 'Failed to bulk toggle test configurations');
  } finally {
    loading.value = false;
  }
};

const handleBulkToggleValidators = async (items: Array<{ id: string; enabled: boolean; reason?: string }>) => {
  try {
    loading.value = true;
    await axios.patch(
      `/api/applications/${applicationId.value}/validators/bulk-toggle`,
      { items }
    );
    await loadValidatorStatuses();
    showBulkValidatorPanel.value = false;
  } catch (err: any) {
    console.error('Error bulk toggling validators:', err);
    alert(err.response?.data?.message || 'Failed to bulk toggle validators');
  } finally {
    loading.value = false;
  }
};

const refreshData = async () => {
  isRefreshing.value = true;
  await Promise.all([
    loadApplication(),
    loadTestConfigStatuses(),
    loadValidatorStatuses(),
  ]);
  setTimeout(() => {
    isRefreshing.value = false;
  }, 500);
};

const formatDate = (date: Date | string): string => {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

onMounted(async () => {
  await loadApplication();
  await loadTestConfigStatuses();
  await loadValidatorStatuses();
});
</script>

<style scoped>
.application-detail-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.detail-content {
  width: 100%;
}

.detail-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  margin-top: 16px;
}

.header-left {
  flex: 1;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-meta {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.action-icon {
  width: 18px;
  height: 18px;
}

.action-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.content-section {
  margin-bottom: 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  display: flex;
  align-items: center;
  gap: 12px;
}

.section-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.info-value {
  font-size: 1rem;
  color: #ffffff;
  font-weight: 500;
}

.toggles-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.loading {
  text-align: center;
  padding: 50px;
  color: #4facfe;
  font-size: 1.2em;
}

.error {
  text-align: center;
  padding: 20px;
  color: #fc8181;
  font-size: 1.2em;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  margin: 20px 0;
}
</style>

