<template>
  <div class="config-validation-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Configuration Validation</h1>
          <p class="page-description">Manage and validate external system configurations</p>
        </div>
        <button @click="showAddTargetModal = true" class="btn-primary">
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
        v-for="target in targets"
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

    <div v-if="!loading && !error && targets.length === 0" class="empty-state">
      <Shield class="empty-icon" />
      <h3>No validation targets configured</h3>
      <p>Add your first validation target to start validating external system configurations</p>
      <button @click="showAddTargetModal = true" class="btn-primary">
        <Plus class="btn-icon" />
        Add Validation Target
      </button>
    </div>

    <!-- Add/Edit Target Modal -->
    <AddValidationTargetModal
      :show="showAddTargetModal"
      :target="editingTarget"
      @close="showAddTargetModal = false; editingTarget = null"
      @submit="handleTargetSubmit"
    />

    <!-- Rules Modal -->
    <ValidationRulesModal
      :show="showRulesModal"
      :target="selectedTarget"
      :rules="selectedTarget ? getTargetRules(selectedTarget.id) : []"
      @close="showRulesModal = false; selectedTarget = null"
      @submit="handleRulesSubmit"
    />

    <!-- Results Modal -->
    <ValidationResultsModal
      :show="showResultsModal"
      :target="selectedTarget"
      :results="selectedTarget ? getTargetResults(selectedTarget.id) : []"
      @close="showResultsModal = false; selectedTarget = null"
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

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Configuration Validation' }
];

const loading = ref(false);
const error = ref<string | null>(null);
const targets = ref<any[]>([]);
const rules = ref<any[]>([]);
const results = ref<any[]>([]);
const showAddTargetModal = ref(false);
const editingTarget = ref<any>(null);
const showRulesModal = ref(false);
const showResultsModal = ref(false);
const selectedTarget = ref<any>(null);
const runningValidation = ref<string | null>(null);

const loadTargets = async () => {
  try {
    loading.value = true;
    error.value = null;
    const [targetsRes, rulesRes, resultsRes] = await Promise.all([
      axios.get('/api/validation-targets'),
      axios.get('/api/validation-targets').then(() => []).catch(() => []), // Rules loaded per target
      axios.get('/api/validation-targets').then(() => []).catch(() => []), // Results loaded per target
    ]);
    targets.value = targetsRes.data.map((t: any) => ({
      ...t,
      createdAt: new Date(t.createdAt),
      updatedAt: new Date(t.updatedAt),
      lastValidationAt: t.lastValidationAt ? new Date(t.lastValidationAt) : null,
      nextScheduledRun: t.nextScheduledRun ? new Date(t.nextScheduledRun) : null,
    }));
  } catch (err: any) {
    error.value = err.message || 'Failed to load validation targets';
    console.error('Error loading targets:', err);
  } finally {
    loading.value = false;
  }
};

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
  showAddTargetModal.value = true;
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
  showRulesModal.value = true;
};

const viewResults = async (target: any) => {
  selectedTarget.value = target;
  await loadResultsForTarget(target.id);
  showResultsModal.value = true;
};

const handleTargetSubmit = async (data: any) => {
  try {
    if (editingTarget.value) {
      await axios.patch(`/api/validation-targets/${editingTarget.value.id}`, data);
    } else {
      await axios.post('/api/validation-targets', data);
    }
    await loadTargets();
    showAddTargetModal.value = false;
    editingTarget.value = null;
  } catch (err: any) {
    console.error('Error saving target:', err);
    alert(err.response?.data?.message || 'Failed to save target');
  }
};

const handleRulesSubmit = async () => {
  await loadTargets();
  showRulesModal.value = false;
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
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
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
  color: #4facfe;
  font-size: 1.1rem;
}

.error {
  color: #fc8181;
  font-size: 1.1rem;
  margin-bottom: 16px;
}

.btn-retry {
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-retry:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.targets-list {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.target-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.2s;
}

.target-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.target-header {
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.target-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.target-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.target-type {
  font-size: 0.875rem;
  color: #718096;
  margin: 0;
  text-transform: capitalize;
}

.target-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-healthy {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-warnings {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-errors {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-unknown {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.target-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin: 8px 0 0 0;
}

.target-stats {
  display: flex;
  gap: 24px;
  margin-bottom: 20px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.stat-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-label {
  font-size: 0.875rem;
  color: #718096;
}

.stat-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.target-actions {
  display: flex;
  gap: 8px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.view-btn:hover {
  background: rgba(79, 172, 254, 0.1);
}

.edit-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.run-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 24px;
}
</style>

