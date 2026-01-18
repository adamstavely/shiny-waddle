<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Data Classification</h1>
          <p class="page-description">Manage data classification levels and rules</p>
        </div>
      </div>
    </div>
    <div class="empty-state">
      <p>Data Classification page - To be implemented</p>
      <p>This page will contain the data classification tab content from Policies.vue</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import Breadcrumb from '../../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Data Classification' }
];
</script>

<style scoped>
.policies-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 24px;
}

.page-title {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0;
}

.empty-state {
  text-align: center;
  padding: 60px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  color: #a0aec0;
}
</style>
