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
