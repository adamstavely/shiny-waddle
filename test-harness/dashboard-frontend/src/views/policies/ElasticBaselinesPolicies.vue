<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Elastic Baselines</h1>
          <p class="page-description">Manage Elastic configuration baselines</p>
        </div>
        <button @click="openCreateBaselineModal" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
    </div>

    <div class="config-sections">
      <div class="config-section">
        <h3 class="config-section-title">Cluster Settings Baseline</h3>
        <p class="config-description">Define baseline cluster settings configurations</p>
        <div class="empty-state">
          <Server class="empty-icon" />
          <p>Cluster settings management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Index Templates</h3>
        <p class="config-description">Manage baseline index template configurations</p>
        <div class="empty-state">
          <p>Index template management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">ILM Policies</h3>
        <p class="config-description">Configure baseline Index Lifecycle Management policies</p>
        <div class="empty-state">
          <p>ILM policy management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Role Definitions</h3>
        <p class="config-description">Define baseline Elasticsearch role configurations</p>
        <div class="empty-state">
          <p>Role definition management coming soon</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Server, Plus } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Elastic Baselines' }
];

const openCreateBaselineModal = () => {
  alert('Create baseline modal - Feature coming soon');
};
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
</style>
