<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Data Contracts</h1>
          <p class="page-description">Manage data contract configurations</p>
        </div>
        <button @click="openCreateContractModal" class="btn-primary">
          <Plus class="btn-icon" />
          Create Contract
        </button>
      </div>
    </div>

    <div class="config-sections">
      <div class="config-section">
        <h3 class="config-section-title">Contract Registry</h3>
        <p class="config-description">Manage registered data contracts and their versions</p>
        <div v-if="loadingContracts" class="loading-state">
          <div class="loading-spinner"></div>
          <p>Loading contracts...</p>
        </div>
        <div v-else-if="dataContracts.length === 0" class="empty-state">
          <Database class="empty-icon" />
          <h3>No data contracts registered</h3>
          <p>Create your first data contract to get started</p>
          <button @click="openCreateContractModal" class="btn-primary">Create Contract</button>
        </div>
        <div v-else class="config-list">
          <div v-for="contract in dataContracts" :key="contract.id" class="config-item">
            <div class="config-item-header">
              <h4>{{ contract.name }}</h4>
              <span class="config-version">v{{ contract.version || '1.0.0' }}</span>
            </div>
            <p class="config-description">{{ contract.description || 'No description' }}</p>
            <div class="config-item-actions">
              <button class="action-btn edit-btn">View</button>
              <button class="action-btn delete-btn">Delete</button>
            </div>
          </div>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Baseline Schemas</h3>
        <p class="config-description">Define baseline schemas for contract validation</p>
        <div class="empty-state">
          <p>Schema management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Classification Policies</h3>
        <p class="config-description">Configure PII and data classification policies</p>
        <div class="empty-state">
          <p>Classification policy management coming soon</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Database, Plus } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Data Contracts' }
];

const dataContracts = ref<any[]>([]);
const loadingContracts = ref(false);

const loadContracts = async () => {
  loadingContracts.value = true;
  try {
    // Try to load from API when available
    const response = await axios.get('/api/v1/data-contracts').catch(() => null);
    if (response?.data) {
      dataContracts.value = response.data;
    }
  } catch (err) {
    // API not available yet, use empty array
    dataContracts.value = [];
  } finally {
    loadingContracts.value = false;
  }
};

const openCreateContractModal = () => {
  alert('Create contract modal - Feature coming soon. API endpoint: POST /api/v1/data-contracts');
};

onMounted(() => {
  loadContracts();
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

.config-sections {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.config-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.config-section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.config-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  margin: 0 0 var(--spacing-md) 0;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.config-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.config-item {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
}

.config-item-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.config-item-header h4 {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.config-version {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-primary);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto var(--spacing-md);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.config-item-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.action-btn {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  border: var(--border-width-thin) solid var(--border-color-primary);
  background: var(--color-bg-overlay-light);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.action-btn:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--border-color-muted);
}

.edit-btn:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.delete-btn:hover {
  border-color: var(--color-error);
  color: var(--color-error);
}
</style>
