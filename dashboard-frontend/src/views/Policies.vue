<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Access Control</h1>
          <p class="page-description">Manage access control policies, data classification, and exceptions</p>
        </div>
      </div>
    </div>

    <!-- Grouped Tab Navigation -->
    <div class="tab-navigation-wrapper">
      <!-- Access Control Policies Group -->
      <div class="tab-group">
        <div class="tab-group-header">
          <Shield class="group-icon" />
          <span class="group-label">Access Control</span>
        </div>
        <div class="tab-group-tabs">
          <button
            v-for="tab in accessControlTabs"
            :key="tab.id"
            @click="handleTabChange(tab.id)"
            class="tab-button"
            :class="{ 'tab-active': activeTab === tab.id }"
          >
            <component :is="tab.icon" class="tab-icon" />
            <span class="tab-label">{{ tab.label }}</span>
            <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
          </button>
        </div>
      </div>

      <!-- Data Policies Group -->
      <div class="tab-group">
        <div class="tab-group-tabs">
          <button
            v-for="tab in dataPoliciesTabs"
            :key="tab.id"
            @click="handleTabChange(tab.id)"
            class="tab-button"
            :class="{ 'tab-active': activeTab === tab.id }"
          >
            <component :is="tab.icon" class="tab-icon" />
            <span class="tab-label">{{ tab.label }}</span>
            <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
          </button>
        </div>
      </div>

    </div>

    <!-- Tab Content -->
    <div class="tab-content-wrapper">
      <AccessControlPolicies v-if="activeTab === 'access-control'" />
      <DataClassificationPolicies v-else-if="activeTab === 'data-classification'" />
      <ExceptionsPolicies v-else-if="activeTab === 'exceptions'" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  Shield,
  FileText,
  Settings,
  AlertTriangle,
  Database,
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import AccessControlPolicies from './policies/AccessControlPolicies.vue';
import DataClassificationPolicies from './policies/DataClassificationPolicies.vue';
import ExceptionsPolicies from './policies/ExceptionsPolicies.vue';
import axios from 'axios';

const route = useRoute();
const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Access Control' }
];

// Initialize active tab from route query or default
const activeTab = ref<'access-control' | 'data-classification' | 'exceptions'>(
  (route.query.tab as any) || 'access-control'
);

// Policy counts for badges (can be loaded from API)
const policyCounts = ref({
  accessControl: 0,
  dataClassification: 0,
  exceptions: 0
});

// Access Control Policies Group
const accessControlTabs = computed(() => [
  { 
    id: 'access-control', 
    label: 'Access Control', 
    icon: Shield, 
    badge: policyCounts.value.accessControl || undefined 
  },
  { 
    id: 'exceptions', 
    label: 'Exceptions', 
    icon: AlertTriangle,
    badge: policyCounts.value.exceptions || undefined
  }
]);

// Data Policies Group
const dataPoliciesTabs = computed(() => [
  { 
    id: 'data-classification', 
    label: 'Data Classification', 
    icon: FileText,
    badge: policyCounts.value.dataClassification || undefined
  }
]);


const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as any;
  // Update URL without navigation
  router.replace({ query: { ...route.query, tab: tabId } });
};

// Load policy counts for badges
const loadPolicyCounts = async () => {
  try {
    // Load counts from various endpoints
    const [policies, levels, exceptions] = await Promise.allSettled([
      axios.get('/api/policies').then(r => r.data),
      axios.get('/api/data-classification/levels').then(r => r.data).catch(() => []),
      axios.get('/api/policies/exceptions').then(r => r.data).catch(() => [])
    ]);

    policyCounts.value = {
      accessControl: policies.status === 'fulfilled' ? policies.value.length : 0,
      dataClassification: levels.status === 'fulfilled' ? levels.value.length : 0,
      exceptions: exceptions.status === 'fulfilled' ? exceptions.value.length : 0
    };
  } catch (error) {
    console.error('Error loading policy counts:', error);
  }
};

// Watch for route changes to update active tab
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    // Redirect old baseline tabs and standards-mapping to access-control
    if (['platform-config', 'salesforce', 'elastic', 'idp-platform', 'servicenow', 'data-contracts', 'standards-mapping'].includes(newTab)) {
      router.replace({ query: { ...route.query, tab: 'access-control' } });
      activeTab.value = 'access-control';
    } else {
      activeTab.value = newTab as any;
    }
  }
});

onMounted(() => {
  loadPolicyCounts();
});
</script>

<style scoped>
.policies-page {
  padding: var(--spacing-lg);
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.tab-navigation-wrapper {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
  padding-bottom: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.tab-group-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-xs) 0;
  margin-bottom: var(--spacing-xs);
}

.group-icon {
  width: 18px;
  height: 18px;
  color: var(--color-primary);
  opacity: 0.8;
}

.group-label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.tab-group-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
  padding-left: calc(var(--spacing-lg) + var(--spacing-sm));
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  white-space: nowrap;
}

.tab-button:hover {
  background: var(--color-bg-overlay-dark);
  border-color: var(--border-color-primary-hover);
  color: var(--color-text-primary);
}

.tab-button.tab-active {
  background: var(--color-info-bg);
  border-color: var(--color-primary);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
}

.tab-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.tab-label {
  flex: 1;
}

.tab-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 var(--spacing-xs);
  background: var(--color-primary);
  color: var(--color-text-primary);
  border-radius: var(--border-radius-full);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  margin-left: var(--spacing-xs);
}

.tab-button.tab-active .tab-badge {
  background: var(--color-text-primary);
  color: var(--color-primary);
}

.tab-content-wrapper {
  margin-top: var(--spacing-lg);
}

@media (max-width: 768px) {
  .tab-group-tabs {
    flex-direction: column;
    padding-left: 0;
  }
  
  .tab-button {
    width: 100%;
    justify-content: flex-start;
  }
}
</style>
