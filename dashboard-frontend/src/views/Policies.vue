<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Policies & Configuration</h1>
          <p class="page-description">Manage access control policies, data policies, platform baselines, and configurations</p>
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
        <div class="tab-group-header">
          <Database class="group-icon" />
          <span class="group-label">Data Policies</span>
        </div>
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

      <!-- Platform Baselines Group -->
      <div class="tab-group">
        <div class="tab-group-header">
          <Settings class="group-icon" />
          <span class="group-label">Platform Baselines</span>
        </div>
        <div class="tab-group-tabs">
          <button
            v-for="tab in platformBaselinesTabs"
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
      <StandardsMappingPolicies v-else-if="activeTab === 'standards-mapping'" />
      <DataContractsPolicies v-else-if="activeTab === 'data-contracts'" />
      <SalesforceBaselinesPolicies v-else-if="activeTab === 'salesforce'" />
      <ElasticBaselinesPolicies v-else-if="activeTab === 'elastic'" />
      <IDPPlatformPolicies v-else-if="activeTab === 'idp-platform'" />
      <ServiceNowBaselinesPolicies v-else-if="activeTab === 'servicenow'" />
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
  CheckCircle2,
  Database,
  Cloud,
  Server,
  Container,
  Workflow
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import AccessControlPolicies from './policies/AccessControlPolicies.vue';
import DataClassificationPolicies from './policies/DataClassificationPolicies.vue';
import ExceptionsPolicies from './policies/ExceptionsPolicies.vue';
import StandardsMappingPolicies from './policies/StandardsMappingPolicies.vue';
import DataContractsPolicies from './policies/DataContractsPolicies.vue';
import SalesforceBaselinesPolicies from './policies/SalesforceBaselinesPolicies.vue';
import ElasticBaselinesPolicies from './policies/ElasticBaselinesPolicies.vue';
import IDPPlatformPolicies from './policies/IDPPlatformPolicies.vue';
import ServiceNowBaselinesPolicies from './policies/ServiceNowBaselinesPolicies.vue';
import axios from 'axios';

const route = useRoute();
const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies & Config' }
];

// Initialize active tab from route query or default
const activeTab = ref<'access-control' | 'data-classification' | 'exceptions' | 'standards-mapping' | 'data-contracts' | 'salesforce' | 'elastic' | 'idp-platform' | 'servicenow'>(
  (route.query.tab as any) || 'access-control'
);

// Policy counts for badges (can be loaded from API)
const policyCounts = ref({
  accessControl: 0,
  dataClassification: 0,
  exceptions: 0,
  standardsMapping: 0,
  dataContracts: 0,
  salesforce: 0,
  elastic: 0,
  idpPlatform: 0,
  servicenow: 0
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
  },
  { 
    id: 'data-contracts', 
    label: 'Data Contracts', 
    icon: Database,
    badge: policyCounts.value.dataContracts || undefined
  },
  { 
    id: 'standards-mapping', 
    label: 'Standards Mapping', 
    icon: CheckCircle2,
    badge: policyCounts.value.standardsMapping || undefined
  }
]);

// Platform Baselines Group
const platformBaselinesTabs = computed(() => [
  { 
    id: 'salesforce', 
    label: 'Salesforce', 
    icon: Cloud,
    badge: policyCounts.value.salesforce || undefined
  },
  { 
    id: 'elastic', 
    label: 'Elastic', 
    icon: Server,
    badge: policyCounts.value.elastic || undefined
  },
  { 
    id: 'idp-platform', 
    label: 'IDP / Kubernetes', 
    icon: Container,
    badge: policyCounts.value.idpPlatform || undefined
  },
  { 
    id: 'servicenow', 
    label: 'ServiceNow', 
    icon: Workflow,
    badge: policyCounts.value.servicenow || undefined
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
    const [policies, levels, exceptions, standards, contracts, salesforceBaselines, elasticBaselines, idpBaselines, servicenowBaselines] = await Promise.allSettled([
      axios.get('/api/policies').then(r => r.data),
      axios.get('/api/data-classification/levels').then(r => r.data).catch(() => []),
      axios.get('/api/policies/exceptions').then(r => r.data).catch(() => []),
      axios.get('/api/standards').then(r => r.data).catch(() => []),
      axios.get('/api/data-contracts').then(r => r.data).catch(() => []),
      axios.get('/api/v1/salesforce/baselines').then(r => r.data).catch(() => []),
      axios.get('/api/v1/elastic/baselines').then(r => r.data).catch(() => []),
      axios.get('/api/v1/idp-kubernetes/baselines').then(r => r.data).catch(() => []),
      axios.get('/api/v1/servicenow/baselines').then(r => r.data).catch(() => [])
    ]);

    policyCounts.value = {
      accessControl: policies.status === 'fulfilled' ? policies.value.length : 0,
      dataClassification: levels.status === 'fulfilled' ? levels.value.length : 0,
      exceptions: exceptions.status === 'fulfilled' ? exceptions.value.length : 0,
      standardsMapping: standards.status === 'fulfilled' ? standards.value.length : 0,
      dataContracts: contracts.status === 'fulfilled' ? contracts.value.length : 0,
      salesforce: salesforceBaselines.status === 'fulfilled' ? (salesforceBaselines.value?.length || 0) : 0,
      elastic: elasticBaselines.status === 'fulfilled' ? (elasticBaselines.value?.length || 0) : 0,
      idpPlatform: idpBaselines.status === 'fulfilled' ? (idpBaselines.value?.length || 0) : 0,
      servicenow: servicenowBaselines.status === 'fulfilled' ? (servicenowBaselines.value?.length || 0) : 0
    };
  } catch (error) {
    console.error('Error loading policy counts:', error);
  }
};

// Watch for route changes to update active tab
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    // Redirect platform-config to salesforce if someone has an old URL
    if (newTab === 'platform-config') {
      router.replace({ query: { ...route.query, tab: 'salesforce' } });
      activeTab.value = 'salesforce';
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
