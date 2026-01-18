<template>
  <div class="test-library-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Library</h1>
          <p class="page-description">Different categories of security tests (API Gateway, DLP, Network Policies, etc.). Each test type has specific test functions you can run.</p>
        </div>
      </div>
    </div>
    
    <div class="test-types-grid">
      <TestTypeCard
        v-for="testType in testTypes"
        :key="testType.type"
        :name="testType.name"
        :type="testType.type"
        :description="testType.description"
        :icon="testType.icon"
        :config-count="getConfigCountForType(testType.type)"
        :last-run-status="getLastRunStatusForType(testType.type)"
        @edit-config="handleEditConfig"
        @view-result="handleViewResult"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Server,
  FileX,
  Network,
  Lock,
  Database
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestTypeCard from '../components/TestTypeCard.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test Library' }
];

const testTypes = [
  { name: 'API Gateway', type: 'api-gateway', description: 'Test API gateway policies, rate limiting, and service authentication', icon: Server },
  { name: 'DLP', type: 'dlp', description: 'Test data exfiltration detection, API response validation, and bulk export controls', icon: FileX },
  { name: 'Network Policies', type: 'network-policy', description: 'Test firewall rules, network segmentation, and service mesh policies', icon: Network },
  { name: 'API Security', type: 'api-security', description: 'Test REST and GraphQL API security', icon: Lock },
  { name: 'RLS/CLS', type: 'rls-cls', description: 'Test row-level and column-level security', icon: Database },
  { name: 'Distributed Systems', type: 'distributed-systems', description: 'Test distributed system policies, multi-region consistency, and synchronization', icon: Server },
  { name: 'Data Pipeline', type: 'data-pipeline', description: 'Test ETL pipelines, streaming data, and pipeline security', icon: Server },
];

const configurations = ref<any[]>([]);
const lastRunStatusForTypes = ref<Record<string, string>>({});

const getConfigCountForType = (type: string): number => {
  return configurations.value.filter(c => c.type === type).length;
};

const getLastRunStatusForType = (type: string): string => {
  return lastRunStatusForTypes.value[type] || 'unknown';
};

const loadConfigurations = async () => {
  // Test configurations removed - infrastructure is now part of applications
  // Return empty array for now
  configurations.value = [];
};

const loadLastRunStatusForTypes = async () => {
  try {
    const response = await axios.get('/api/test-results?limit=1000');
    if (response.data) {
      const statusMap: Record<string, string> = {};
      testTypes.forEach(testType => {
        const typeResults = response.data.filter((r: any) => r.testType === testType.type);
        if (typeResults.length > 0) {
          const latest = typeResults.sort((a: any, b: any) => 
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          )[0];
          statusMap[testType.type] = latest.status === 'passed' ? 'passed' : 'failed';
        } else {
          statusMap[testType.type] = 'unknown';
        }
      });
      lastRunStatusForTypes.value = statusMap;
    }
  } catch (err) {
    console.error('Error loading last run status:', err);
  }
};

const handleEditConfig = (type: string) => {
  // Test configurations removed - navigate to applications to manage infrastructure
  router.push({ path: '/applications' });
};

const handleViewResult = (type: string) => {
  router.push({ path: '/tests/findings', query: { type } });
};

onMounted(async () => {
  await Promise.all([
    loadConfigurations(),
    loadLastRunStatusForTypes()
  ]);
});
</script>

<style scoped>
.test-library-page {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.test-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
}
</style>

