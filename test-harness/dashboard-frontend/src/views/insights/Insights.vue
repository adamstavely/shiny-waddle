<template>
  <div class="insights-view">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Tab Navigation -->
    <div class="insights-header">
      <div class="header-left">
        <h1 class="page-title">Insights</h1>
        <p class="page-description">Comprehensive analytics, dashboards, and reporting</p>
      </div>
      <div class="tab-navigation">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          @click="updateTab(tab.id)"
          :class="['tab-button', { active: activeTab === tab.id }]"
        >
          <component :is="tab.icon" class="tab-icon" />
          <span>{{ tab.label }}</span>
        </button>
      </div>
    </div>

    <!-- Tab Content -->
    <div class="tab-content">
      <OverviewTab 
        v-if="activeTab === 'overview'" 
        :shared-filters="sharedFilters"
        @update-filters="updateSharedFilters"
      />
      <AnalyticsTab 
        v-if="activeTab === 'analytics'" 
        :shared-filters="sharedFilters"
        @update-filters="updateSharedFilters"
      />
      <ReportsTab 
        v-if="activeTab === 'reports'" 
        :shared-filters="sharedFilters"
        @update-filters="updateSharedFilters"
      />
      <PredictionsTab 
        v-if="activeTab === 'predictions'" 
        :shared-filters="sharedFilters"
        @update-filters="updateSharedFilters"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { LayoutDashboard, BarChart3, FileText, TrendingUp } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import OverviewTab from './OverviewTab.vue';
import AnalyticsTab from './AnalyticsTab.vue';
import ReportsTab from './ReportsTab.vue';
import PredictionsTab from './PredictionsTab.vue';

const route = useRoute();
const router = useRouter();

// Shared filters across tabs
const sharedFilters = ref({
  timeRange: '30',
  applications: [] as string[],
  teams: [] as string[],
  categories: [] as string[]
});

const tabs = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'predictions', label: 'Predictions', icon: TrendingUp }
];

// Determine active tab from route query or default to overview
const activeTab = ref<string>(
  (route.query.tab as string) || 'overview'
);

// Update URL when tab changes
const updateTab = (tabId: string) => {
  activeTab.value = tabId;
  router.replace({ query: { ...route.query, tab: tabId } });
};

const updateSharedFilters = (filters: any) => {
  sharedFilters.value = { ...sharedFilters.value, ...filters };
};

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights' }
];

// Watch for route changes
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    activeTab.value = newTab;
  }
});

onMounted(() => {
  // Handle tab from query param
  if (route.query.tab) {
    activeTab.value = route.query.tab as string;
  }
});
</script>

<style scoped>
.insights-view {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.insights-header {
  margin-bottom: 32px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.header-left {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
}

.tab-navigation {
  display: flex;
  gap: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  padding-bottom: 0;
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
  bottom: -1px;
}

.tab-button:hover {
  color: #ffffff;
  background: rgba(79, 172, 254, 0.05);
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
  background: rgba(79, 172, 254, 0.05);
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  min-height: 400px;
}
</style>

