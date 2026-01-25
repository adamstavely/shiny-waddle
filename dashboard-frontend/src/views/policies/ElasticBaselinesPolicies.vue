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
  font-size: 1.1rem;
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
  font-size: 0.9rem;
  margin: 0 0 var(--spacing-md) 0;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}
</style>
