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
  color: #0f1419;
  border: none;
  border-radius: 12px;
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

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #4facfe;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 24px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: #a0aec0;
  font-size: 1rem;
}

.error-state {
  text-align: center;
  padding: 40px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 12px;
  margin-bottom: 24px;
}

.error-icon {
  width: 48px;
  height: 48px;
  color: #fc8181;
  margin: 0 auto 16px;
}

.error-state p {
  color: #fc8181;
  font-size: 1rem;
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

.empty-state {
  text-align: center;
  padding: 60px 40px;
  color: #a0aec0;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.empty-state p {
  margin: 0 0 24px 0;
}

.baselines-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.baseline-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.3s;
}

.baseline-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.baseline-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.baseline-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.baseline-environment {
  padding: 4px 12px;
  border-radius: 12px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.baseline-description {
  color: #a0aec0;
  font-size: 0.9rem;
  margin: 12px 0;
  line-height: 1.5;
}

.baseline-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}

.action-btn {
  padding: 8px 16px;
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  background: rgba(15, 20, 25, 0.6);
  color: #ffffff;
  cursor: pointer;
  font-size: 0.875rem;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(79, 172, 254, 0.1);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.edit-btn:hover {
  border-color: #4facfe;
  color: #4facfe;
}

.delete-btn:hover {
  border-color: #fc8181;
  color: #fc8181;
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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
