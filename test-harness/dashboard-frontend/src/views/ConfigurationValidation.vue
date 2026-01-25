<template>
  <div class="config-validation-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Configuration Validation</h1>
          <p class="page-description">Manage and validate external system configurations</p>
        </div>
        <button @click="modals.open('addTarget')" class="btn-primary">
          <Plus class="btn-icon" />
          Add Validation Target
        </button>
      </div>
    </div>

    <!-- Loading/Error States -->
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading validation targets...</div>
    </div>
    <div v-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <button @click="loadTargets" class="btn-retry">
        Retry
      </button>
    </div>

    <!-- Validation Targets List -->
    <div v-if="!loading && !error" class="targets-list">
      <div
        v-for="target in (targets || [])"
        :key="target.id"
        class="target-card"
      >
        <div class="target-header">
          <div class="target-title-row">
            <div>
              <h3 class="target-name">{{ target.name }}</h3>
              <p class="target-type">{{ target.type }}</p>
            </div>
            <span class="target-status" :class="`status-${target.status}`">
              {{ getStatusLabel(target.status) }}
            </span>
          </div>
          <p v-if="target.description" class="target-description">{{ target.description }}</p>
        </div>

        <div class="target-stats">
          <div class="stat-item">
            <span class="stat-label">Rules</span>
            <span class="stat-value">{{ getTargetRules(target.id).length }}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Last Run</span>
            <span class="stat-value">{{ target.lastValidationAt ? formatDate(target.lastValidationAt) : 'Never' }}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Next Run</span>
            <span class="stat-value">{{ target.nextScheduledRun ? formatDate(target.nextScheduledRun) : 'Not scheduled' }}</span>
          </div>
        </div>

        <div class="target-actions">
          <button @click="viewResults(target)" class="action-btn view-btn">
            <FileText class="action-icon" />
            View Results
          </button>
          <button @click="editRules(target)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit Rules
          </button>
          <button @click="runValidation(target)" class="action-btn run-btn" :disabled="runningValidation === target.id">
            <Play class="action-icon" />
            {{ runningValidation === target.id ? 'Running...' : 'Run Now' }}
          </button>
          <button @click="editTarget(target)" class="action-btn edit-btn">
            <Settings class="action-icon" />
            Edit
          </button>
          <button @click="deleteTarget(target)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="!loading && !error && (!targets || targets.length === 0)" class="empty-state">
      <Shield class="empty-icon" />
      <h3>No validation targets configured</h3>
      <p>Add your first validation target to start validating external system configurations</p>
      <button @click="modals.open('addTarget')" class="btn-primary">
        <Plus class="btn-icon" />
        Add Validation Target
      </button>
    </div>

    <!-- Add/Edit Target Modal -->
    <AddValidationTargetModal
      :show="modals.isOpen('addTarget')"
      :target="editingTarget"
      @close="modals.close('addTarget'); editingTarget = null"
      @submit="handleTargetSubmit"
    />

    <!-- Rules Modal -->
    <ValidationRulesModal
      :show="modals.isOpen('rules')"
      :target="selectedTarget"
      :rules="selectedTarget ? getTargetRules(selectedTarget.id) : []"
      @close="modals.close('rules'); selectedTarget = null"
      @submit="handleRulesSubmit"
    />

    <!-- Results Modal -->
    <ValidationResultsModal
      :show="modals.isOpen('results')"
      :target="selectedTarget"
      :results="selectedTarget ? getTargetResults(selectedTarget.id) : []"
      @close="modals.close('results'); selectedTarget = null"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import axios from 'axios';
import { Shield, Plus, FileText, Edit, Play, Settings, Trash2 } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import AddValidationTargetModal from '../components/AddValidationTargetModal.vue';
import ValidationRulesModal from '../components/ValidationRulesModal.vue';
import ValidationResultsModal from '../components/ValidationResultsModal.vue';
import { useApiDataAuto } from '../composables/useApiData';
import { useMultiModal } from '../composables/useModal';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Configuration Validation' }
];

const rules = ref<any[]>([]);
const results = ref<any[]>([]);
const runningValidation = ref<string | null>(null);

// Use composable for API data fetching
const { data: targets, loading, error, reload: loadTargets } = useApiDataAuto(
  async () => {
    const targetsRes = await axios.get('/api/validation-targets');
    return targetsRes.data.map((t: any) => ({
      ...t,
      createdAt: new Date(t.createdAt),
      updatedAt: new Date(t.updatedAt),
      lastValidationAt: t.lastValidationAt ? new Date(t.lastValidationAt) : null,
      nextScheduledRun: t.nextScheduledRun ? new Date(t.nextScheduledRun) : null,
    }));
  },
  {
    initialData: [],
    errorMessage: 'Failed to load validation targets',
  }
);

// Use composable for modal state management
const modals = useMultiModal(['addTarget', 'rules', 'results']);
const editingTarget = ref<any>(null);
const selectedTarget = ref<any>(null);

const loadRulesForTarget = async (targetId: string) => {
  try {
    const response = await axios.get(`/api/validation-targets/${targetId}/rules`);
    const targetRules = response.data.map((r: any) => ({
      ...r,
      createdAt: new Date(r.createdAt),
      updatedAt: new Date(r.updatedAt),
    }));
    // Merge with existing rules
    rules.value = rules.value.filter(r => r.targetId !== targetId).concat(targetRules);
  } catch (err) {
    console.error('Error loading rules:', err);
  }
};

const loadResultsForTarget = async (targetId: string) => {
  try {
    const response = await axios.get(`/api/validation-targets/${targetId}/results`);
    const targetResults = response.data.map((r: any) => ({
      ...r,
      timestamp: new Date(r.timestamp),
    }));
    // Merge with existing results
    results.value = results.value.filter(r => r.targetId !== targetId).concat(targetResults);
  } catch (err) {
    console.error('Error loading results:', err);
  }
};

const getTargetRules = (targetId: string) => {
  return rules.value.filter(r => r.targetId === targetId);
};

const getTargetResults = (targetId: string) => {
  return results.value.filter(r => r.targetId === targetId);
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

const editTarget = (target: any) => {
  editingTarget.value = target;
  modals.open('addTarget');
};

const deleteTarget = async (target: any) => {
  if (!confirm(`Are you sure you want to delete validation target "${target.name}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/validation-targets/${target.id}`);
    await loadTargets();
  } catch (err: any) {
    console.error('Error deleting target:', err);
    alert(err.response?.data?.message || 'Failed to delete target');
  }
};

const runValidation = async (target: any) => {
  try {
    runningValidation.value = target.id;
    const response = await axios.post(`/api/validation-targets/${target.id}/validate`);
    await loadTargets();
    await loadResultsForTarget(target.id);
    alert(response.data.message || 'Validation completed');
  } catch (err: any) {
    console.error('Error running validation:', err);
    alert(err.response?.data?.message || 'Failed to run validation');
  } finally {
    runningValidation.value = null;
  }
};

const editRules = async (target: any) => {
  selectedTarget.value = target;
  await loadRulesForTarget(target.id);
  modals.open('rules');
};

const viewResults = async (target: any) => {
  selectedTarget.value = target;
  await loadResultsForTarget(target.id);
  modals.open('results');
};

const handleTargetSubmit = async (data: any) => {
  try {
    if (editingTarget.value) {
      await axios.patch(`/api/validation-targets/${editingTarget.value.id}`, data);
    } else {
      await axios.post('/api/validation-targets', data);
    }
    await loadTargets();
    modals.close('addTarget');
    editingTarget.value = null;
  } catch (err: any) {
    console.error('Error saving target:', err);
    alert(err.response?.data?.message || 'Failed to save target');
  }
};

const handleRulesSubmit = async () => {
  await loadTargets();
  modals.close('rules');
  selectedTarget.value = null;
};

onMounted(() => {
  loadTargets();
});
</script>

<style scoped>
.config-validation-page {
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
  gap: 24px;
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: 1.1rem;
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
  padding: 40px;
  text-align: center;
}

.loading {
  color: var(--color-primary);
  font-size: 1.1rem;
}

.error {
  color: var(--color-error);
  font-size: 1.1rem;
  margin-bottom: var(--spacing-md);
}

.btn-retry {
  padding: 10px var(--spacing-xl);
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

.targets-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.target-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.target-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.target-header {
  margin-bottom: var(--spacing-xl);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.target-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.target-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.target-type {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
  margin: 0;
  text-transform: capitalize;
}

.target-status {
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

.target-description {
  font-size: 0.9rem;
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0 0 0;
}

.target-stats {
  display: flex;
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-lg);
}

.stat-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.stat-value {
  font-size: 0.9rem;
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.target-actions {
  display: flex;
  gap: var(--spacing-sm);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
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
  padding: 80px 40px;
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

