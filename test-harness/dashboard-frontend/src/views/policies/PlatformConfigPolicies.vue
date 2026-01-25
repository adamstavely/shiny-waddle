<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Platform Config</h1>
          <p class="page-description">Manage platform configuration baselines</p>
        </div>
        <button @click="openCreateBaselineModal" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
    </div>

    <div v-if="loadingBaselines" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading baselines...</p>
    </div>

    <div v-else-if="baselinesError" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ baselinesError }}</p>
      <button @click="loadBaselines" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="baselines.length === 0" class="empty-state">
      <Settings class="empty-icon" />
      <h3>No baselines defined</h3>
      <p>Create your first platform configuration baseline to get started</p>
      <button @click="openCreateBaselineModal" class="btn-primary">Create First Baseline</button>
    </div>

    <div v-else class="baselines-grid">
      <div v-for="baseline in baselines" :key="baseline.id" class="baseline-card">
        <div class="baseline-header">
          <h3 class="baseline-name">{{ baseline.name }}</h3>
          <span class="baseline-environment">{{ baseline.environment || 'default' }}</span>
        </div>
        <p class="baseline-description">{{ baseline.description || 'No description' }}</p>
        <div class="baseline-actions">
          <button @click="compareBaseline(baseline.id)" class="action-btn edit-btn">Compare</button>
          <button @click="detectDrift(baseline.id)" class="action-btn edit-btn">Detect Drift</button>
          <button @click="deleteBaseline(baseline.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <!-- Create Baseline Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateBaselineModal" class="modal-overlay" @click="closeBaselineModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Settings class="modal-title-icon" />
                <h2>Create Baseline</h2>
              </div>
              <button @click="closeBaselineModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveBaseline" class="form">
                <div class="form-group">
                  <label>Baseline Name</label>
                  <input v-model="baselineForm.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Description</label>
                  <textarea v-model="baselineForm.description" rows="3"></textarea>
                </div>
                <div class="form-group">
                  <label>Environment</label>
                  <input v-model="baselineForm.environment" type="text" placeholder="e.g., production, staging" />
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeBaselineModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    Create Baseline
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  Settings,
  Plus,
  Trash2,
  AlertTriangle,
  X
} from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Platform Config' }
];

// Data
const baselines = ref<any[]>([]);
const loadingBaselines = ref(false);
const baselinesError = ref<string | null>(null);

// Modal
const showCreateBaselineModal = ref(false);

// Form
const baselineForm = ref({
  name: '',
  description: '',
  environment: ''
});

// API Calls
const loadBaselines = async () => {
  loadingBaselines.value = true;
  baselinesError.value = null;
  try {
    const response = await axios.get('/api/v1/platform-config/baselines');
    baselines.value = response.data || [];
  } catch (err: any) {
    baselinesError.value = err.response?.data?.message || 'Failed to load baselines';
    console.error('Error loading baselines:', err);
  } finally {
    loadingBaselines.value = false;
  }
};

// Actions
const openCreateBaselineModal = () => {
  baselineForm.value = { name: '', description: '', environment: '' };
  showCreateBaselineModal.value = true;
};

const closeBaselineModal = () => {
  showCreateBaselineModal.value = false;
};

const saveBaseline = async () => {
  try {
    await axios.post('/api/v1/platform-config/baselines', baselineForm.value);
    await loadBaselines();
    closeBaselineModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to create baseline');
    console.error('Error creating baseline:', err);
  }
};

const compareBaseline = async (id: string) => {
  alert(`Compare baseline ${id} - Feature coming soon`);
};

const detectDrift = async (id: string) => {
  alert(`Detect drift for baseline ${id} - Feature coming soon`);
};

const deleteBaseline = async (id: string) => {
  if (confirm('Are you sure you want to delete this baseline?')) {
    try {
      await axios.delete(`/api/v1/platform-config/baselines/${id}`);
      await loadBaselines();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete baseline');
      console.error('Error deleting baseline:', err);
    }
  }
};

onMounted(() => {
  loadBaselines();
});
</script>

<style scoped>
.policies-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
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
  color: var(--color-bg-primary);
  border: none;
  border-radius: var(--border-radius-lg);
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

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-primary);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto var(--spacing-lg);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.error-state {
  text-align: center;
  padding: var(--spacing-2xl);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-lg);
  margin-bottom: var(--spacing-lg);
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
}

.error-state p {
  color: var(--color-error);
  font-size: var(--font-size-base);
  margin-bottom: var(--spacing-md);
}

.btn-retry {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-retry:hover {
  background: var(--border-color-primary);
  opacity: 0.2;
  border-color: var(--border-color-primary-active);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.empty-state p {
  margin: 0 0 24px 0;
}

.baselines-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: var(--spacing-lg);
}

.baseline-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.baseline-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.baseline-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.baseline-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.baseline-environment {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.baseline-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.baseline-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-md);
}

.action-btn {
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
  background: var(--color-bg-overlay-light);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  transition: var(--transition-all);
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--border-color-muted);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.edit-btn:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.delete-btn:hover {
  border-color: var(--color-error);
  color: var(--color-error);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-index-modal);
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
