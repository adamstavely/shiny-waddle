<template>
  <div class="rls-cls-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">RLS/CLS Testing</h1>
          <p class="page-description">Test Row-Level Security and Column-Level Security policies</p>
        </div>
        <div class="header-actions">
          <button @click="navigateToConfig" class="btn-secondary">
            <Settings class="btn-icon" />
            Configure
          </button>
        </div>
      </div>
    </div>

    <!-- Configuration Selector -->
    <div class="config-selector">
      <div class="selector-group">
        <label>Use Configuration:</label>
        <select v-model="selectedConfigId" @change="loadConfiguration">
          <option value="">None (Use Defaults)</option>
          <option v-for="config in configurations" :key="config.id" :value="config.id">
            {{ config.name }}
          </option>
        </select>
      </div>
      <div class="selector-actions">
        <button @click="saveCurrentAsConfig" class="btn-secondary" :disabled="!hasTestData">
          <Save class="btn-icon" />
          Save as Configuration
        </button>
      </div>
      <div v-if="selectedConfigId" class="active-config">
        <CheckCircle2 class="icon" />
        <span>Using: {{ getConfigName(selectedConfigId) }}</span>
      </div>
    </div>

    <div class="test-sections">
      <div class="test-card">
        <div class="card-header">
          <ShieldCheck class="card-icon" />
          <h2 class="card-title">RLS Coverage</h2>
        </div>
        <p class="card-description">Test Row-Level Security policy coverage across all database tables</p>
        <button @click="testRLSCoverage" class="btn-primary" :disabled="loading">
          <Play v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test RLS Coverage' }}
        </button>
        <div v-if="rlsCoverage" class="results">
          <div class="result-item">
            <span class="result-label">Coverage</span>
            <span class="result-value">{{ rlsCoverage.coveragePercentage.toFixed(1) }}%</span>
          </div>
          <div class="result-item">
            <span class="result-label">Tables with RLS</span>
            <span class="result-value">{{ rlsCoverage.tablesWithRLS }}/{{ rlsCoverage.totalTables }}</span>
          </div>
          <div v-if="rlsCoverage.tablesWithoutRLS.length > 0" class="warning-box">
            <AlertTriangle class="warning-icon" />
            <span>{{ rlsCoverage.tablesWithoutRLS.length }} tables missing RLS policies</span>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <ShieldCheck class="card-icon" />
          <h2 class="card-title">CLS Coverage</h2>
        </div>
        <p class="card-description">Test Column-Level Security policy coverage for sensitive data</p>
        <button @click="testCLSCoverage" class="btn-primary" :disabled="loading">
          <Play v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test CLS Coverage' }}
        </button>
        <div v-if="clsCoverage" class="results">
          <div class="result-item">
            <span class="result-label">Coverage</span>
            <span class="result-value">{{ clsCoverage.coveragePercentage.toFixed(1) }}%</span>
          </div>
          <div class="result-item">
            <span class="result-label">Tables with CLS</span>
            <span class="result-value">{{ clsCoverage.tablesWithCLS }}/{{ clsCoverage.totalTables }}</span>
          </div>
        </div>
      </div>

      <div class="test-card">
        <div class="card-header">
          <Shield class="card-icon" />
          <h2 class="card-title">Cross-Tenant Isolation</h2>
        </div>
        <p class="card-description">Verify that tenants cannot access each other's data</p>
        <button @click="testCrossTenant" class="btn-primary" :disabled="loading">
          <Play v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Testing...' : 'Test Isolation' }}
        </button>
        <div v-if="isolationTest" class="results">
          <div class="result-status" :class="isolationTest.isolationVerified ? 'status-success' : 'status-error'">
            <CheckCircle2 v-if="isolationTest.isolationVerified" class="status-icon" />
            <XCircle v-else class="status-icon" />
            <span>{{ isolationTest.isolationVerified ? 'Isolation Verified' : 'Isolation Failed' }}</span>
          </div>
          <div v-if="isolationTest.violations.length > 0" class="violations-list">
            <p class="violations-title">Violations:</p>
            <ul>
              <li v-for="(violation, idx) in isolationTest.violations" :key="idx">{{ violation }}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { ShieldCheck, Shield, Play, AlertTriangle, CheckCircle2, XCircle, Settings, Save } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'RLS/CLS Testing', to: '/rls-cls' },
];

const router = useRouter();
const loading = ref(false);
const rlsCoverage = ref<any>(null);
const clsCoverage = ref<any>(null);
const isolationTest = ref<any>(null);
const selectedConfigId = ref<string>('');
const configurations = ref<any[]>([]);
const currentDatabase = ref<any>({ type: 'postgresql', database: 'test' });
const currentTestQueries = ref<any[]>([]);

const hasTestData = computed(() => {
  return currentDatabase.value.type || currentTestQueries.value.length > 0;
});

const getConfigName = (id: string) => {
  const config = configurations.value.find(c => c.id === id);
  return config?.name || id;
};

const loadConfigurations = async () => {
  try {
    const response = await axios.get('/api/test-configurations?type=rls-cls');
    configurations.value = response.data;
  } catch (error) {
    console.error('Error loading configurations:', error);
  }
};

const loadConfiguration = async () => {
  if (!selectedConfigId.value) {
    return;
  }
  try {
    const response = await axios.get(`/api/test-configurations/${selectedConfigId.value}`);
    const config = response.data;
    if (config.database) {
      currentDatabase.value = config.database;
    }
    if (config.testQueries) {
      currentTestQueries.value = config.testQueries;
    }
  } catch (error) {
    console.error('Error loading configuration:', error);
  }
};

const saveCurrentAsConfig = async () => {
  const name = prompt('Enter configuration name:');
  if (!name) return;
  try {
    await axios.post('/api/test-configurations', {
      name,
      type: 'rls-cls',
      database: currentDatabase.value,
      testQueries: currentTestQueries.value,
    });
    await loadConfigurations();
    alert('Configuration saved successfully!');
  } catch (error: any) {
    alert('Error saving configuration: ' + (error.response?.data?.message || error.message));
  }
};

const navigateToConfig = () => {
  router.push('/test-configurations');
};

const testRLSCoverage = async () => {
  loading.value = true;
  try {
    const payload: any = {};
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    } else {
      payload.database = currentDatabase.value;
    }
    const response = await axios.post('/api/rls-cls/test-rls-coverage', payload);
    rlsCoverage.value = response.data;
  } catch (error) {
    console.error('Error testing RLS coverage:', error);
  } finally {
    loading.value = false;
  }
};

const testCLSCoverage = async () => {
  loading.value = true;
  try {
    const payload: any = {};
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    } else {
      payload.database = currentDatabase.value;
    }
    const response = await axios.post('/api/rls-cls/test-cls-coverage', payload);
    clsCoverage.value = response.data;
  } catch (error) {
    console.error('Error testing CLS coverage:', error);
  } finally {
    loading.value = false;
  }
};

const testCrossTenant = async () => {
  loading.value = true;
  try {
    const payload: any = {
      tenant1: 'tenant1',
      tenant2: 'tenant2',
    };
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    } else {
      payload.testQueries = currentTestQueries.value.length > 0
        ? currentTestQueries.value
        : [
            {
              name: 'test-cross-tenant-query',
              sql: 'SELECT * FROM users WHERE tenant_id = ?',
              expectedResult: [],
            },
          ];
    }
    const response = await axios.post('/api/rls-cls/test-cross-tenant-isolation', payload);
    isolationTest.value = response.data;
  } catch (error) {
    console.error('Error testing cross-tenant isolation:', error);
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadConfigurations();
});
</script>

<style scoped>
.rls-cls-page {
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
  flex-wrap: wrap;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.test-sections {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 24px;
}

.test-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  transition: all 0.3s;
}

.test-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.card-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.card-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 20px;
  line-height: 1.5;
}

.btn-primary {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  width: 100%;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: #ffffff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.results {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.result-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.result-item:last-child {
  border-bottom: none;
}

.result-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.result-value {
  font-size: 1rem;
  color: #ffffff;
  font-weight: 600;
}

.result-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  border-radius: 8px;
  font-weight: 600;
  margin-bottom: 12px;
}

.status-success {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.status-error {
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.status-icon {
  width: 20px;
  height: 20px;
}

.warning-box {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
  color: #fbbf24;
  font-size: 0.875rem;
  margin-top: 12px;
}

.warning-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.violations-list {
  margin-top: 12px;
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
}

.violations-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #fc8181;
  margin-bottom: 8px;
}

.violations-list ul {
  margin: 0;
  padding-left: 20px;
  color: #fc8181;
  font-size: 0.875rem;
}

.violations-list li {
  margin-bottom: 4px;
}

.header-actions {
  display: flex;
  gap: 1rem;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-secondary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.config-selector {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.selector-group {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.selector-group label {
  color: #a0aec0;
  font-weight: 500;
  font-size: 0.9rem;
}

.selector-group select {
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.9rem;
  min-width: 200px;
}

.selector-group select:focus {
  outline: none;
  border-color: #4facfe;
}

.selector-actions {
  margin-left: auto;
}

.active-config {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 8px 12px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 6px;
  color: #22c55e;
  font-size: 0.875rem;
}

.active-config .icon {
  width: 16px;
  height: 16px;
}
</style>

