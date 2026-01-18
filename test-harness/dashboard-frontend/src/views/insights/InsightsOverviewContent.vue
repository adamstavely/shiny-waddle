<template>
  <div class="insights-overview-content-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Overview</h1>
          <p class="page-description">Comprehensive analytics dashboard</p>
        </div>
      </div>
    </div>

    <!-- Use the OverviewTab component content -->
    <OverviewTab 
      :shared-filters="sharedFilters"
      @update-filters="updateSharedFilters"
    />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import Breadcrumb from '../../components/Breadcrumb.vue';
import OverviewTab from './OverviewTab.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights & Reports', to: '/insights' },
  { label: 'Overview' }
];

const sharedFilters = ref({
  timeRange: '30',
  applications: [] as string[],
  teams: [] as string[],
  categories: [] as string[]
});

const updateSharedFilters = (filters: any) => {
  sharedFilters.value = { ...sharedFilters.value, ...filters };
};
</script>

<style scoped>
.insights-overview-content-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
}
</style>
