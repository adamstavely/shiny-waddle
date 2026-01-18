<template>
  <div class="insights-analytics-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Analytics</h1>
          <p class="page-description">Comprehensive analytics and dashboards</p>
        </div>
        <button @click="openGenerateModal" class="btn-primary">
          <FileText class="btn-icon" />
          Generate Report
        </button>
      </div>
    </div>

    <!-- Use the ReportsTab component content -->
    <ReportsTab 
      :shared-filters="sharedFilters"
      @update-filters="updateSharedFilters"
    />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { FileText } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import ReportsTab from './ReportsTab.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights & Reports', to: '/insights' },
  { label: 'Analytics' }
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

const openGenerateModal = () => {
  // Handle generate report modal
  console.log('Generate report');
};
</script>

<style scoped>
.insights-analytics-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
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
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.3);
}

.btn-icon {
  width: 18px;
  height: 18px;
}
</style>
