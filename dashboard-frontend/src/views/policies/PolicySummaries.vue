<template>
  <div class="policy-summaries-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Policy Summaries</h1>
          <p class="page-description">Generate and view AI-powered summaries of policy changes and compliance status</p>
        </div>
      </div>
    </div>

    <AISummaryView />
  </div>
</template>

<script setup lang="ts">
import Breadcrumb from '../../components/Breadcrumb.vue';
import AISummaryView from '../../components/policies/AISummaryView.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies/access-control' },
  { label: 'Summaries' }
];
</script>

<style scoped>
.policy-summaries-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-lg);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}
</style>
