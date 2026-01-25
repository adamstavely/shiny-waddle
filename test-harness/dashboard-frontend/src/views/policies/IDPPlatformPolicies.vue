<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">IDP / Kubernetes</h1>
          <p class="page-description">Manage IDP and Kubernetes configuration baselines</p>
        </div>
        <button @click="openCreateBaselineModal" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
    </div>

    <div class="config-sections">
      <div class="config-section">
        <h3 class="config-section-title">Golden Path Templates</h3>
        <p class="config-description">Manage golden path service templates</p>
        <div class="empty-state">
          <Container class="empty-icon" />
          <p>Template management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Pod Security Standards</h3>
        <p class="config-description">Configure Kubernetes Pod Security Standards</p>
        <div class="empty-state">
          <p>Pod security standards management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Approved Registries</h3>
        <p class="config-description">Define approved container image registries</p>
        <div class="empty-state">
          <p>Registry management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Allowed Sidecars</h3>
        <p class="config-description">Configure approved sidecar containers</p>
        <div class="empty-state">
          <p>Sidecar management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Cluster-wide Policies</h3>
        <p class="config-description">Manage cluster-wide policy configurations</p>
        <div class="empty-state">
          <p>Cluster policy management coming soon</p>
        </div>
      </div>
      <div class="config-section">
        <h3 class="config-section-title">Network Policy Baselines</h3>
        <p class="config-description">Define baseline network policy configurations</p>
        <div class="empty-state">
          <p>Network policy management coming soon</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Container, Plus } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'IDP / Kubernetes' }
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
