<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Policies</h1>
          <p class="page-description">Manage RBAC and ABAC access control policies</p>
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
      <AccessControlPolicies v-if="activeTab === 'access-control'" />
      <DataClassificationPolicies v-else-if="activeTab === 'data-classification'" />
      <PlatformConfigPolicies v-else-if="activeTab === 'platform-config'" />
      <ExceptionsPolicies v-else-if="activeTab === 'exceptions'" />
      <StandardsMappingPolicies v-else-if="activeTab === 'standards-mapping'" />
      <DataContractsPolicies v-else-if="activeTab === 'data-contracts'" />
      <SalesforceBaselinesPolicies v-else-if="activeTab === 'salesforce'" />
      <ElasticBaselinesPolicies v-else-if="activeTab === 'elastic'" />
      <IDPPlatformPolicies v-else-if="activeTab === 'idp-platform'" />
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
  Container
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TabNavigation, { type Tab } from '../components/TabNavigation.vue';
import AccessControlPolicies from './policies/AccessControlPolicies.vue';
import DataClassificationPolicies from './policies/DataClassificationPolicies.vue';
import PlatformConfigPolicies from './policies/PlatformConfigPolicies.vue';
import ExceptionsPolicies from './policies/ExceptionsPolicies.vue';
import StandardsMappingPolicies from './policies/StandardsMappingPolicies.vue';
import DataContractsPolicies from './policies/DataContractsPolicies.vue';
import SalesforceBaselinesPolicies from './policies/SalesforceBaselinesPolicies.vue';
import ElasticBaselinesPolicies from './policies/ElasticBaselinesPolicies.vue';
import IDPPlatformPolicies from './policies/IDPPlatformPolicies.vue';
import axios from 'axios';

const route = useRoute();
const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies' }
];

// Initialize active tab from route query or default
const activeTab = ref<'access-control' | 'data-classification' | 'platform-config' | 'exceptions' | 'standards-mapping' | 'data-contracts' | 'salesforce' | 'elastic' | 'idp-platform'>(
  (route.query.tab as any) || 'access-control'
);

// Policy counts for badges (can be loaded from API)
const policyCounts = ref({
  accessControl: 0,
  dataClassification: 0,
  platformConfig: 0,
  exceptions: 0,
  standardsMapping: 0,
  dataContracts: 0,
  salesforce: 0,
  elastic: 0,
  idpPlatform: 0
});

const tabs = computed<Tab[]>(() => [
  { 
    id: 'access-control', 
    label: 'Access Control', 
    icon: Shield, 
    badge: policyCounts.value.accessControl || undefined 
  },
  { 
    id: 'data-classification', 
    label: 'Data Classification', 
    icon: FileText,
    badge: policyCounts.value.dataClassification || undefined
  },
  { 
    id: 'platform-config', 
    label: 'Platform Config', 
    icon: Settings,
    badge: policyCounts.value.platformConfig || undefined
  },
  { 
    id: 'exceptions', 
    label: 'Exceptions', 
    icon: AlertTriangle,
    badge: policyCounts.value.exceptions || undefined
  },
  { 
    id: 'standards-mapping', 
    label: 'Standards Mapping', 
    icon: CheckCircle2,
    badge: policyCounts.value.standardsMapping || undefined
  },
  { 
    id: 'data-contracts', 
    label: 'Data Contracts', 
    icon: Database,
    badge: policyCounts.value.dataContracts || undefined
  },
  { 
    id: 'salesforce', 
    label: 'Salesforce Baselines', 
    icon: Cloud,
    badge: policyCounts.value.salesforce || undefined
  },
  { 
    id: 'elastic', 
    label: 'Elastic Baselines', 
    icon: Server,
    badge: policyCounts.value.elastic || undefined
  },
  { 
    id: 'idp-platform', 
    label: 'IDP / Kubernetes', 
    icon: Container,
    badge: policyCounts.value.idpPlatform || undefined
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
    const [policies, levels, baselines, exceptions, standards, contracts, salesforceBaselines, elasticBaselines, idpBaselines] = await Promise.allSettled([
      axios.get('/api/policies').then(r => r.data),
      axios.get('/api/data-classification/levels').then(r => r.data).catch(() => []),
      axios.get('/api/platform-config/baselines').then(r => r.data).catch(() => []),
      axios.get('/api/policies/exceptions').then(r => r.data).catch(() => []),
      axios.get('/api/standards').then(r => r.data).catch(() => []),
      axios.get('/api/data-contracts').then(r => r.data).catch(() => []),
      axios.get('/api/salesforce/baselines').then(r => r.data).catch(() => []),
      axios.get('/api/elastic/baselines').then(r => r.data).catch(() => []),
      axios.get('/api/idp/baselines').then(r => r.data).catch(() => [])
    ]);

    policyCounts.value = {
      accessControl: policies.status === 'fulfilled' ? policies.value.length : 0,
      dataClassification: levels.status === 'fulfilled' ? levels.value.length : 0,
      platformConfig: baselines.status === 'fulfilled' ? baselines.value.length : 0,
      exceptions: exceptions.status === 'fulfilled' ? exceptions.value.length : 0,
      standardsMapping: standards.status === 'fulfilled' ? standards.value.length : 0,
      dataContracts: contracts.status === 'fulfilled' ? contracts.value.length : 0,
      salesforce: salesforceBaselines.status === 'fulfilled' ? salesforceBaselines.value.length : 0,
      elastic: elasticBaselines.status === 'fulfilled' ? elasticBaselines.value.length : 0,
      idpPlatform: idpBaselines.status === 'fulfilled' ? idpBaselines.value.length : 0
    };
  } catch (error) {
    console.error('Error loading policy counts:', error);
  }
};

// Watch for route changes to update active tab
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    activeTab.value = newTab as any;
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

.tab-content-wrapper {
  margin-top: var(--spacing-lg);
}
</style>
