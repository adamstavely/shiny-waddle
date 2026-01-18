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

.config-sections {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.config-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.config-section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.config-description {
  color: #a0aec0;
  font-size: 0.9rem;
  margin: 0 0 16px 0;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.config-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.config-item {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.config-item-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.config-item-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.config-version {
  padding: 4px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
}

.loading-state {
  text-align: center;
  padding: 40px;
  color: #4facfe;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 16px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: #a0aec0;
  font-size: 0.9rem;
}

.config-item-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}

.action-btn {
  padding: 6px 12px;
  border-radius: 6px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  background: rgba(15, 20, 25, 0.6);
  color: #ffffff;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.action-btn:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(79, 172, 254, 0.1);
}

.edit-btn:hover {
  border-color: #4facfe;
  color: #4facfe;
}

.delete-btn:hover {
  border-color: #fc8181;
  color: #fc8181;
}
</style>
