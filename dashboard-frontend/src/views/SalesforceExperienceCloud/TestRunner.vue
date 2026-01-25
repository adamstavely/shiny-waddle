<template>
  <div class="test-runner-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div v-if="loadingConfig" class="loading">Loading configuration...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loadingConfig && !error && config" class="test-runner-content">
      <div class="page-header">
        <div class="header-content">
          <div>
            <h1 class="page-title">Run Tests</h1>
            <p class="page-description">Configuration: {{ config.name }}</p>
          </div>
        </div>
      </div>

      <div class="test-selection">
        <h2 class="section-title">Select Tests to Run</h2>
        <div class="tests-grid">
          <div
            v-for="test in availableTests"
            :key="test.type"
            class="test-card"
            :class="{ 'running': runningTests[test.type], 'completed': testResults[test.type] }"
          >
            <div class="test-header">
              <component :is="test.icon" class="test-icon" />
              <h3 class="test-name">{{ test.name }}</h3>
            </div>
            <p class="test-description">{{ test.description }}</p>
            
            <div v-if="test.type === 'object-access'" class="test-options">
              <label>Objects (comma-separated):</label>
              <input
                v-model="objectListInput"
                type="text"
                class="form-input"
                placeholder="Account, Contact, Lead"
                :disabled="runningTests[test.type]"
              />
            </div>

            <div v-if="test.requiresAuth" class="test-options">
              <label>Cookies (optional override):</label>
              <textarea
                v-model="cookiesInput"
                class="form-input"
                rows="2"
                placeholder="sid=...;"
                :disabled="runningTests[test.type]"
              />
            </div>

            <button
              @click="runTest(test.type)"
              class="test-btn"
              :disabled="runningTests[test.type] || runningAnyTest"
            >
              <Play v-if="!runningTests[test.type]" class="btn-icon" />
              <div v-else class="loading-spinner-small"></div>
              {{ runningTests[test.type] ? 'Running...' : 'Run Test' }}
            </button>

            <div v-if="testResults[test.type]" class="test-result">
              <div class="result-status" :class="getStatusClass(testResults[test.type].status)">
                <CheckCircle2 v-if="testResults[test.type].status === 'passed'" class="status-icon" />
                <XCircle v-else-if="testResults[test.type].status === 'failed'" class="status-icon" />
                <AlertCircle v-else class="status-icon" />
                <span>{{ testResults[test.type].status.toUpperCase() }}</span>
              </div>
              <button @click="viewResult(testResults[test.type].id)" class="view-result-btn">
                View Details
              </button>
            </div>
          </div>
        </div>

        <div class="bulk-actions">
          <button @click="runFullAudit" class="btn-primary" :disabled="runningAnyTest">
            <Play class="btn-icon" />
            {{ runningFullAudit ? 'Running Full Audit...' : 'Run Full Audit' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Play, CheckCircle2, XCircle, AlertCircle, Shield, Key, Database, Users, Home, Search } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import { useSalesforceExperienceCloud } from '../../composables/useSalesforceExperienceCloud';
import type { SalesforceExperienceCloudConfigEntity, SalesforceExperienceCloudTestResultEntity } from '../../types/salesforce-experience-cloud';

const route = useRoute();
const router = useRouter();
const {
  loading: apiLoading,
  error: apiError,
  getConfig,
  runGuestAccessTest,
  runAuthenticatedAccessTest,
  runGraphQLTest,
  runSelfRegistrationTest,
  runRecordListTest,
  runHomeURLTest,
  runObjectAccessTest,
  runFullAudit: runFullAuditApi,
} = useSalesforceExperienceCloud();

const config = ref<SalesforceExperienceCloudConfigEntity | null>(null);
const configId = route.params.id as string;
const loadingConfig = ref(false);
const error = ref<string | null>(null);
const runningTests = ref<Record<string, boolean>>({});
const runningFullAudit = ref(false);
const testResults = ref<Record<string, SalesforceExperienceCloudTestResultEntity>>({});
const objectListInput = ref('');
const cookiesInput = ref('');

const availableTests = [
  {
    type: 'guest-access',
    name: 'Guest Access Test',
    description: 'Test accessible records from Guest context',
    icon: Users,
    requiresAuth: false,
  },
  {
    type: 'authenticated-access',
    name: 'Authenticated Access Test',
    description: 'Test accessible records from authenticated context',
    icon: Shield,
    requiresAuth: true,
  },
  {
    type: 'graphql',
    name: 'GraphQL Capability Test',
    description: 'Check GraphQL Aura method availability',
    icon: Database,
    requiresAuth: false,
  },
  {
    type: 'self-registration',
    name: 'Self-Registration Test',
    description: 'Check for self-registration capabilities',
    icon: Key,
    requiresAuth: false,
  },
  {
    type: 'record-lists',
    name: 'Record List Components Test',
    description: 'Discover Record List components',
    icon: Search,
    requiresAuth: false,
  },
  {
    type: 'home-urls',
    name: 'Home URL Test',
    description: 'Discover Home URLs with admin access',
    icon: Home,
    requiresAuth: false,
  },
  {
    type: 'object-access',
    name: 'Object Access Test',
    description: 'Test access to specific objects',
    icon: Database,
    requiresAuth: false,
  },
];

const runningAnyTest = computed(() => {
  return Object.values(runningTests.value).some(running => running) || runningFullAudit.value;
});

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Salesforce Experience Cloud', to: '/salesforce-experience-cloud' },
  { label: config.value?.name || 'Test Runner', to: '' },
]);

const loadConfig = async () => {
  loadingConfig.value = true;
  error.value = null;
  try {
    config.value = await getConfig(configId);
  } catch (err: any) {
    error.value = err.message || 'Failed to load configuration';
  } finally {
    loadingConfig.value = false;
  }
};

const runTest = async (testType: string) => {
  if (!config.value) return;

  runningTests.value[testType] = true;
  error.value = null;

  try {
    let result: SalesforceExperienceCloudTestResultEntity;

    switch (testType) {
      case 'guest-access':
        result = await runGuestAccessTest(configId, cookiesInput.value || undefined);
        break;
      case 'authenticated-access':
        result = await runAuthenticatedAccessTest(configId, cookiesInput.value || undefined);
        break;
      case 'graphql':
        result = await runGraphQLTest(configId);
        break;
      case 'self-registration':
        result = await runSelfRegistrationTest(configId);
        break;
      case 'record-lists':
        result = await runRecordListTest(configId);
        break;
      case 'home-urls':
        result = await runHomeURLTest(configId);
        break;
      case 'object-access':
        if (!objectListInput.value.trim()) {
          alert('Please enter at least one object name');
          return;
        }
        const objects = objectListInput.value.split(',').map(s => s.trim()).filter(Boolean);
        result = await runObjectAccessTest(configId, objects);
        break;
      default:
        throw new Error(`Unknown test type: ${testType}`);
    }

    testResults.value[testType] = result;
  } catch (err: any) {
    error.value = err.message || `Failed to run ${testType} test`;
    console.error(`Failed to run ${testType} test:`, err);
  } finally {
    runningTests.value[testType] = false;
  }
};

const runFullAudit = async () => {
  if (!config.value) return;

  runningFullAudit.value = true;
  error.value = null;

  try {
    const results = await runFullAuditApi(configId);
    
    // Map results by test type
    results.forEach(result => {
      testResults.value[result.testType] = result;
    });
  } catch (err: any) {
    error.value = err.message || 'Failed to run full audit';
    console.error('Failed to run full audit:', err);
  } finally {
    runningFullAudit.value = false;
  }
};

const viewResult = (resultId: string) => {
  router.push(`/salesforce-experience-cloud/results/${resultId}`);
};

const getStatusClass = (status: string) => {
  return {
    'status-passed': status === 'passed',
    'status-failed': status === 'failed',
    'status-warning': status === 'warning',
  };
};

onMounted(() => {
  loadConfig();
});
</script>

<style scoped>
.test-runner-page {
  padding: 2rem;
}

.page-header {
  margin-bottom: 2rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.page-description {
  color: #666;
}

.test-selection {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 2rem;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
}

.tests-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.test-card {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  transition: all 0.2s;
}

.test-card.running {
  border-color: #6366f1;
  background: #f0f4ff;
}

.test-card.completed {
  border-color: #10b981;
}

.test-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.test-icon {
  width: 24px;
  height: 24px;
  color: #6366f1;
}

.test-name {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
}

.test-description {
  color: #666;
  font-size: 0.9rem;
  margin-bottom: 1rem;
}

.test-options {
  margin-bottom: 1rem;
}

.test-options label {
  display: block;
  font-weight: 500;
  margin-bottom: 0.25rem;
  font-size: 0.9rem;
}

.form-input {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.9rem;
}

.test-btn {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: #6366f1;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.test-btn:hover:not(:disabled) {
  background: #4f46e5;
}

.test-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.test-result {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #e0e0e0;
}

.result-status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.status-passed {
  color: #10b981;
}

.status-failed {
  color: #ef4444;
}

.status-warning {
  color: #f59e0b;
}

.status-icon {
  width: 18px;
  height: 18px;
}

.view-result-btn {
  width: 100%;
  padding: 0.5rem;
  background: #f3f4f6;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.view-result-btn:hover {
  background: #e5e7eb;
}

.bulk-actions {
  display: flex;
  justify-content: center;
  padding-top: 2rem;
  border-top: 1px solid #e0e0e0;
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  background: #6366f1;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-primary:hover:not(:disabled) {
  background: #4f46e5;
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
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
