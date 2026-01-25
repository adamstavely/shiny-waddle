<template>
  <div class="admin-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Admin</h1>
          <p class="page-description">Manage Heimdall configuration and registered applications</p>
        </div>
      </div>
    </div>

    <!-- Tab Navigation -->
    <TabNavigation
      :tabs="tabs"
      :activeTab="activeTab"
      @tab-change="handleTabChange"
    />

    <!-- Tab Content -->
    <div class="tab-content-wrapper">
      <AdminOverviewTab
        v-if="activeTab === 'overview'"
        :applications-count="applicationsCount"
        :active-applications="activeApplications"
        :inactive-applications="inactiveApplications"
        @register-app="handleRegisterApp"
        @run-system-test="runSystemTest"
        @view-logs="viewSystemLogs"
        @export-config="exportConfiguration"
      />
      <AdminBannersTab v-else-if="activeTab === 'banners'" />
      <AdminApplicationsTab v-else-if="activeTab === 'applications'" />
      <AdminValidatorsTab v-else-if="activeTab === 'validators'" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  BarChart3,
  Layers,
  Megaphone,
  Shield
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TabNavigation, { type Tab } from '../components/TabNavigation.vue';
import AdminOverviewTab from './admin/AdminOverviewTab.vue';
import AdminBannersTab from './admin/AdminBannersTab.vue';
import AdminApplicationsTab from './admin/AdminApplicationsTab.vue';
import AdminValidatorsTab from './admin/AdminValidatorsTab.vue';
import axios from 'axios';

const route = useRoute();
const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin' }
];

// Initialize active tab from route query or default
const activeTab = ref<'overview' | 'applications' | 'banners' | 'validators'>(
  (route.query.tab as string | undefined) || 'overview'
);

// Application counts for overview tab
const applications = ref<any[]>([]);

const tabs = computed<Tab[]>(() => [
  { id: 'overview', label: 'Overview', icon: BarChart3 },
  { id: 'applications', label: 'Applications', icon: Layers },
  { id: 'banners', label: 'Banners', icon: Megaphone },
  { id: 'validators', label: 'Validators', icon: Shield }
]);

const applicationsCount = computed(() => applications.value.length);
const activeApplications = computed(() => applications.value.filter(a => a.status === 'active').length);
const inactiveApplications = computed(() => applications.value.filter(a => a.status === 'inactive').length);

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as any;
  router.replace({ query: { ...route.query, tab: tabId } });
};

const handleRegisterApp = () => {
  activeTab.value = 'applications';
  // The AdminApplicationsTab component will handle showing the modal
};

const runSystemTest = () => {
  console.log('Run system test');
  // In real app: trigger system test
};

const viewSystemLogs = () => {
  console.log('View system logs');
  // In real app: navigate to logs page
};

const exportConfiguration = () => {
  console.log('Export configuration');
  // In real app: download configuration JSON
};

// Load applications for overview stats
const loadApplications = async () => {
  try {
    const response = await axios.get("/api/v1/applications");
    applications.value = response.data;
  } catch (err) {
    console.error('Error loading applications:', err);
  }
};

// Watch for route changes to update active tab
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    activeTab.value = newTab as any;
  }
});

onMounted(() => {
  loadApplications();
});
</script>

<style scoped>
.admin-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
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
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.tab-content-wrapper {
  margin-top: var(--spacing-lg);
}
</style>
