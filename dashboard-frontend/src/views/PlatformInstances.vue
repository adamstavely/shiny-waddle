<template>
  <div class="platform-instances-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Platform Instances</h1>
          <p class="page-description">Manage and validate platform instances against baselines</p>
        </div>
        <button @click="modals.open('addInstance')" class="btn-primary">
          <Plus class="btn-icon" />
          Add Platform Instance
        </button>
      </div>
    </div>

    <!-- Loading/Error States -->
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading platform instances...</div>
    </div>
    <div v-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <button @click="loadInstances" class="btn-retry">
        Retry
      </button>
    </div>

    <!-- Platform Instances List -->
    <div v-if="!loading && !error" class="instances-list">
      <div
        v-for="instance in instances"
        :key="instance.id"
        class="instance-card"
      >
        <div class="instance-header">
          <div class="instance-title-row">
            <div>
              <h3 class="instance-name">{{ instance.name }}</h3>
              <p class="instance-type">{{ instance.type }} • {{ instance.environment || 'N/A' }}</p>
            </div>
            <span class="instance-status" :class="`status-${instance.status}`">
              {{ getStatusLabel(instance.status) }}
            </span>
          </div>
          <p v-if="instance.description" class="instance-description">{{ instance.description }}</p>
        </div>

        <div class="instance-info">
          <div class="info-item">
            <span class="info-label">Baseline:</span>
            <span class="info-value">{{ getBaselineName(instance.baselineId) || 'Not assigned' }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Last Validated:</span>
            <span class="info-value">{{ instance.lastValidationAt ? formatDate(instance.lastValidationAt) : 'Never' }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Next Run:</span>
            <span class="info-value">{{ instance.nextScheduledRun ? formatDate(instance.nextScheduledRun) : 'Not scheduled' }}</span>
          </div>
        </div>

        <div class="instance-actions">
          <button @click="viewResults(instance)" class="action-btn view-btn">
            <FileText class="action-icon" />
            View Results
          </button>
          <button @click="validateInstance(instance)" class="action-btn run-btn" :disabled="runningValidation === instance.id">
            <Play class="action-icon" />
            {{ runningValidation === instance.id ? 'Running...' : 'Validate' }}
          </button>
          <button @click="editInstance(instance)" class="action-btn edit-btn">
            <Settings class="action-icon" />
            Edit
          </button>
          <button @click="deleteInstance(instance)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="!loading && !error && (!instances || instances.length === 0)" class="empty-state">
      <Shield class="empty-icon" />
      <h3>No platform instances configured</h3>
      <p>Add your first platform instance to start validating against baselines</p>
      <button @click="modals.open('addInstance')" class="btn-primary">
        <Plus class="btn-icon" />
        Add Platform Instance
      </button>
    </div>

    <!-- Add/Edit Instance Modal -->
    <AddPlatformInstanceModal
      :show="modals.isOpen('addInstance')"
      :instance="editingInstance"
      :baselines="baselines"
      @close="modals.close('addInstance'); editingInstance = null"
      @submit="handleInstanceSubmit"
    />

    <!-- Results Modal -->
    <ValidationResultsModal
      :show="modals.isOpen('results')"
      :target="selectedInstance"
      :results="selectedInstance ? getInstanceResults(selectedInstance.id) : []"
      @close="modals.close('results'); selectedInstance = null"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import axios from 'axios';
import { Shield, Plus, FileText, Play, Settings, Trash2 } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import AddPlatformInstanceModal from '../components/AddPlatformInstanceModal.vue';
import ValidationResultsModal from '../components/ValidationResultsModal.vue';
import { useApiDataAuto } from '../composables/useApiData';
import { useMultiModal } from '../composables/useModal';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Applications', to: '/applications' },
  { label: 'Platform Instances' }
];

const baselines = ref<any[]>([]);
const results = ref<any[]>([]);
const runningValidation = ref<string | null>(null);

// Use composable for API data fetching
const { data: instances, loading, error, reload: loadInstances } = useApiDataAuto(
  async () => {
    const instancesRes = await axios.get('/api/platform-instances');
    return instancesRes.data.map((i: any) => ({
      ...i,
      createdAt: new Date(i.createdAt),
      updatedAt: new Date(i.updatedAt),
      lastValidationAt: i.lastValidationAt ? new Date(i.lastValidationAt) : null,
      nextScheduledRun: i.nextScheduledRun ? new Date(i.nextScheduledRun) : null,
    }));
  },
  {
    initialData: [],
    errorMessage: 'Failed to load platform instances',
  }
);

// Use composable for modal state management
const modals = useMultiModal(['addInstance', 'results']);
const editingInstance = ref<any>(null);
const selectedInstance = ref<any>(null);

const loadBaselines = async () => {
  try {
    // Load baselines from all platforms
    const [salesforce, elastic, idp, servicenow] = await Promise.all([
      axios.get('/api/v1/salesforce/baselines').catch(() => ({ data: [] })),
      axios.get('/api/v1/elastic/baselines').catch(() => ({ data: [] })),
      axios.get('/api/v1/idp-kubernetes/baselines').catch(() => ({ data: [] })),
      axios.get('/api/v1/servicenow/baselines').catch(() => ({ data: [] })),
    ]);
    
    baselines.value = [
      ...salesforce.data.map((b: any) => ({ ...b, platform: 'salesforce' })),
      ...elastic.data.map((b: any) => ({ ...b, platform: 'elastic' })),
      ...idp.data.map((b: any) => ({ ...b, platform: 'idp-kubernetes' })),
      ...servicenow.data.map((b: any) => ({ ...b, platform: 'servicenow' })),
    ];
  } catch (err) {
    console.error('Error loading baselines:', err);
  }
};

const loadResultsForInstance = async (instanceId: string) => {
  try {
    const response = await axios.get(`/api/platform-instances/${instanceId}/results`);
    const instanceResults = response.data.map((r: any) => ({
      ...r,
      timestamp: new Date(r.timestamp),
    }));
    // Merge with existing results
    results.value = results.value.filter(r => r.targetId !== instanceId).concat(instanceResults);
  } catch (err) {
    console.error('Error loading results:', err);
  }
};

const getInstanceResults = (instanceId: string) => {
  return results.value.filter(r => r.targetId === instanceId);
};

const getBaselineName = (baselineId?: string): string => {
  if (!baselineId) return '';
  const baseline = baselines.value.find(b => b.id === baselineId);
  return baseline ? baseline.name : '';
};

const getStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    healthy: 'Healthy',
    warnings: 'Warnings',
    errors: 'Errors',
    unknown: 'Unknown',
  };
  return labels[status] || status;
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return d.toLocaleDateString();
};

const editInstance = (instance: any) => {
  editingInstance.value = instance;
  modals.open('addInstance');
};

const deleteInstance = async (instance: any) => {
  if (!confirm(`Are you sure you want to delete platform instance "${instance.name}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/platform-instances/${instance.id}`);
    await loadInstances();
  } catch (err: any) {
    console.error('Error deleting instance:', err);
    alert(err.response?.data?.message || 'Failed to delete instance');
  }
};

const validateInstance = async (instance: any) => {
  try {
    runningValidation.value = instance.id;
    const response = await axios.post(`/api/platform-instances/${instance.id}/validate`);
    await loadInstances();
    await loadResultsForInstance(instance.id);
    alert(response.data.message || 'Validation completed');
  } catch (err: any) {
    console.error('Error running validation:', err);
    alert(err.response?.data?.message || 'Failed to run validation');
  } finally {
    runningValidation.value = null;
  }
};

const viewResults = async (instance: any) => {
  selectedInstance.value = instance;
  await loadResultsForInstance(instance.id);
  modals.open('results');
};

const handleInstanceSubmit = async (data: any) => {
  try {
    if (editingInstance.value) {
      await axios.patch(`/api/platform-instances/${editingInstance.value.id}`, data);
    } else {
      await axios.post('/api/platform-instances', data);
    }
    await loadInstances();
    modals.close('addInstance');
    editingInstance.value = null;
  } catch (err: any) {
    console.error('Error saving instance:', err);
    alert(err.response?.data?.message || 'Failed to save instance');
  }
};

onMounted(() => {
  loadInstances();
  loadBaselines();
});
</script>

<style scoped>
.platform-instances-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
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

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-lg);
  color: var(--color-bg-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-state,
.error-state {
  padding: var(--spacing-2xl);
  text-align: center;
}

.loading {
  color: var(--color-primary);
  font-size: var(--font-size-lg);
}

.error {
  color: var(--color-error);
  font-size: var(--font-size-lg);
  margin-bottom: var(--spacing-md);
}

.btn-retry {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: rgba(79, 172, 254, 0.1);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-retry:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: var(--border-color-primary-active);
}

.instances-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.instance-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.instance-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.instance-header {
  margin-bottom: var(--spacing-xl);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.instance-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.instance-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.instance-type {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
  margin: 0;
  text-transform: capitalize;
}

.instance-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.status-healthy {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-warnings {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-errors {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-unknown {
  background: rgba(156, 163, 175, 0.2);
  color: var(--color-text-muted);
}

.instance-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0 0 0;
}

.instance-info {
  display: flex;
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-lg);
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.info-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.info-value {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.instance-actions {
  display: flex;
  gap: var(--spacing-sm);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  flex: 1;
  justify-content: center;
}

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: var(--border-color-primary-active);
}

.action-btn:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.view-btn:hover {
  background: rgba(79, 172, 254, 0.1);
}

.edit-btn:hover {
  background: var(--color-success-bg);
  border-color: var(--color-success);
  color: var(--color-success);
}

.run-btn:hover {
  background: var(--color-warning-bg);
  border-color: var(--color-warning);
  color: var(--color-warning);
}

.delete-btn:hover {
  background: var(--color-error-bg);
  border-color: var(--color-error);
  color: var(--color-error);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}
</style>
