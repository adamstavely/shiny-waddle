<template>
  <div class="test-suite-detail-page">
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading test suite...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <BaseButton label="Retry" @click="loadSuite" />
    </div>
    <div v-else-if="suite || isCreating" class="test-suite-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <div class="suite-title-row">
              <h1 class="page-title">{{ isCreating ? 'Create Test Suite' : suite.name }}</h1>
              <div v-if="!isCreating" class="suite-badges">
                <StatusBadge
                  v-if="suite.sourceType"
                  :status="suite.sourceType === 'typescript' ? 'TS' : 'JSON'"
                  size="sm"
                />
                <StatusBadge :status="suite.status" />
                <StatusBadge :status="suite.enabled ? 'enabled' : 'disabled'" />
              </div>
            </div>
            <p v-if="!isCreating" class="suite-meta">
              {{ suite.application || suite.applicationId }} • {{ suite.team }}
              <span v-if="suite.sourcePath" class="source-path">
                • {{ suite.sourcePath }}
              </span>
            </p>
            <p v-if="!isCreating && suite.description" class="suite-description">{{ suite.description }}</p>
          </div>
          <div class="header-actions">
            <BaseButton
              :label="saving ? 'Saving...' : 'Save'"
              :icon="Save"
              @click="saveSuite"
              :disabled="saving"
            />
            <BaseButton
              v-if="!isCreating"
              label="Run"
              :icon="Play"
              variant="secondary"
              @click="runSuite"
            />
            <BaseButton
              label="Back"
              :icon="ArrowLeft"
              variant="ghost"
              @click="goBack"
            />
          </div>
        </div>
      </div>

      <!-- Creation Guide Banner -->
      <div v-if="isCreating" class="creation-guide">
        <div class="guide-content">
          <Info class="guide-icon" />
          <div class="guide-text">
            <h3>Creating a Test Suite</h3>
            <p><strong>How it works:</strong> Test Suites are collections of pre-made tests. Create individual tests first, then assign them to this suite.</p>
            <ol class="guide-steps">
              <li>Enter basic information (name, application, team, test type)</li>
              <li>Go to the Tests tab to assign existing tests to this suite</li>
              <li>All tests must match the suite's test type</li>
              <li>Save your test suite</li>
            </ol>
          </div>
        </div>
      </div>

      <!-- Tabs (only show when editing existing suite) -->
      <TabNavigation
        v-if="!isCreating"
        :tabs="tabs"
        :activeTab="activeTab"
        @tab-change="handleTabChange"
      />

      <!-- Tab Content -->
      <div class="tab-content-container" :class="{ 'creation-layout': isCreating }">
        <!-- Overview Tab (only for existing suites) -->
        <TestSuiteOverviewTab
          v-if="!isCreating && activeTab === 'overview'"
          :suite="suite"
        />

        <!-- Configuration Tab -->
        <TestSuiteConfigurationTab
          v-if="isCreating || activeTab === 'configuration'"
          :form="form"
          @test-type-change="handleTestTypeChange"
        />

        <!-- Tests Tab -->
        <TestSuiteTestsTab
          v-if="isCreating || activeTab === 'tests'"
          :assigned-tests="assignedTests"
          :test-type="form.testType"
          :policies="policies"
          @add-test="showAddTestModal = true"
          @view-test="viewTest"
          @view-policy="viewPolicy"
          @remove-test="removeTest"
        />
      </div>

      <!-- Add Test Modal -->
      <BaseModal
        :isOpen="showAddTestModal"
        title="Add Tests to Suite"
        @update:isOpen="showAddTestModal = $event"
        @close="showAddTestModal = false"
      >
        <div v-if="!form.testType" class="info-message">
          <Info class="info-icon" />
          <p>Please select a test type in the Configuration tab first.</p>
        </div>
        <div v-else>
          <p class="modal-help">Select tests of type: <strong>{{ getTestTypeLabel(form.testType) }}</strong></p>
          <div v-if="loadingTests" class="loading-state">
            <div class="loading">Loading available tests...</div>
          </div>
          <EmptyState
            v-else-if="availableTests.length === 0"
            title="No available tests found"
            description="Create a test first"
            :show-default-action="false"
          >
            <template #actions>
              <router-link to="/tests/individual">
                <BaseButton label="Create Test" />
              </router-link>
            </template>
          </EmptyState>
          <div v-else class="tests-selector">
            <div
              v-for="test in availableTests"
              :key="test.id"
              class="test-option"
              :class="{ selected: form.testIds.includes(test.id) }"
              @click="toggleTest(test.id)"
            >
              <input
                type="checkbox"
                :checked="form.testIds.includes(test.id)"
                @change="toggleTest(test.id)"
              />
              <div class="test-option-info">
                <div class="test-option-name-row">
                  <span class="test-option-name">{{ test.name }}</span>
                  <StatusBadge :status="`v${test.version}`" size="sm" />
                </div>
                <p v-if="test.description" class="test-option-description">{{ test.description }}</p>
              </div>
            </div>
          </div>
        </div>
        <template #footer>
          <BaseButton v-if="form.testType" label="Cancel" variant="secondary" @click="showAddTestModal = false" />
          <BaseButton v-if="form.testType" label="Add Selected Tests" @click="handleTestsAdded" />
        </template>
      </BaseModal>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TestTube,
  Save,
  Play,
  ArrowLeft,
  Info,
  FileText
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import TabNavigation, { type Tab } from '../components/TabNavigation.vue';
import BaseButton from '../components/BaseButton.vue';
import BaseModal from '../components/BaseModal.vue';
import StatusBadge from '../components/StatusBadge.vue';
import EmptyState from '../components/EmptyState.vue';
import TestSuiteOverviewTab from './test-suites/TestSuiteOverviewTab.vue';
import TestSuiteConfigurationTab from './test-suites/TestSuiteConfigurationTab.vue';
import TestSuiteTestsTab from './test-suites/TestSuiteTestsTab.vue';
import type { TestSuite, Test, Policy } from '../types/test';
import type { AxiosError } from 'axios';

const route = useRoute();
const router = useRouter();

const suiteId = computed(() => {
  if (route.name === 'TestSuiteCreate') {
    return 'new';
  }
  return route.params.id as string;
});

const isCreating = computed(() => suiteId.value === 'new');

const loading = ref(true);
const error = ref<string | null>(null);
const saving = ref(false);
const suite = ref<TestSuite | null>(null);
const activeTab = ref('overview');
const showAddTestModal = ref(false);
const assignedTests = ref<Test[]>([]);
const availableTests = ref<Test[]>([]);
const policies = ref<Policy[]>([]);
const loadingTests = ref(false);

const tabs = computed<Tab[]>(() => [
  { id: 'overview', label: 'Overview', icon: Info },
  { id: 'configuration', label: 'Configuration', icon: FileText },
  { id: 'tests', label: 'Tests', icon: TestTube }
]);

const form = ref({
  name: '',
  application: '',
  team: '',
  testType: '' as string,
  testIds: [] as string[],
  description: '',
  enabled: true,
});

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: isCreating.value ? 'Create Test Suite' : (suite.value?.name || 'Test Suite') },
]);

const getTestTypeLabel = (testType: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
  };
  return labels[testType] || testType;
};

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId;
};

const handleTestTypeChange = (testType: string) => {
  form.value.testType = testType;
  loadAvailableTests();
};

const loadSuite = async () => {
  if (isCreating.value) {
    loading.value = false;
    error.value = null;
    form.value = {
      name: '',
      application: '',
      team: '',
      testType: '',
      testIds: [],
      description: '',
      enabled: true,
    };
    suite.value = null;
    assignedTests.value = [];
    return;
  }

  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/v1/test-suites/${suiteId.value}`);
    const suiteData = response.data;

    suite.value = suiteData;
    form.value = {
      name: suiteData.name || '',
      application: suiteData.application || suiteData.applicationId || '',
      team: suiteData.team || '',
      testType: suiteData.testType || '',
      testIds: suiteData.testIds || [],
      description: suiteData.description || '',
      enabled: suiteData.enabled !== false,
    };

    await loadAssignedTests();
    await loadPolicies();
  } catch (err) {
    const axiosError = err as { response?: { data?: { message?: string } } };
    error.value = axiosError.response?.data?.message || 'Failed to load test suite';
    console.error('Error loading test suite:', err);
  } finally {
    loading.value = false;
  }
};

const loadAssignedTests = async () => {
  if (!form.value.testIds || form.value.testIds.length === 0) {
    assignedTests.value = [];
    return;
  }

  loadingTests.value = true;
  try {
    const testPromises = form.value.testIds.map(id => 
      axios.get(`/api/tests/${id}`).catch(() => null)
    );
    const responses = await Promise.all(testPromises);
    assignedTests.value = responses
      .filter(r => r !== null)
      .map(r => r.data as Test)
      .filter(t => t.testType === form.value.testType);
  } catch (err) {
    console.error('Error loading assigned tests:', err);
    assignedTests.value = [];
  } finally {
    loadingTests.value = false;
  }
};

const loadAvailableTests = async () => {
  if (!form.value.testType) {
    availableTests.value = [];
    return;
  }

  try {
    const response = await axios.get(`/api/v1/tests?testType=${form.value.testType}`);
    availableTests.value = (response.data as Test[]).filter((test) => 
      !form.value.testIds.includes(test.id)
    );
  } catch (err) {
    console.error('Error loading available tests:', err);
    availableTests.value = [];
  }
};

const loadPolicies = async () => {
  try {
    const response = await axios.get('/api/policies');
    policies.value = response.data;
  } catch (err) {
    console.error('Error loading policies:', err);
  }
};

const toggleTest = (testId: string) => {
  const index = form.value.testIds.indexOf(testId);
  if (index === -1) {
    form.value.testIds.push(testId);
  } else {
    form.value.testIds.splice(index, 1);
  }
};

const handleTestsAdded = () => {
  loadAssignedTests();
  showAddTestModal.value = false;
};

const viewTest = (testId: string) => {
  router.push(`/tests/individual/${testId}`);
};

const viewPolicy = (policyId: string) => {
  router.push(`/policies/${policyId}`);
};

const removeTest = (testId: string) => {
  const index = form.value.testIds.indexOf(testId);
  if (index !== -1) {
    form.value.testIds.splice(index, 1);
    loadAssignedTests();
  }
};

const saveSuite = async () => {
  if (!form.value.name || !form.value.application || !form.value.team || !form.value.testType) {
    alert('Please fill in all required fields (name, application, team, test type)');
    return;
  }

  saving.value = true;
  try {
    const payload = {
      name: form.value.name,
      application: form.value.application,
      team: form.value.team,
      testType: form.value.testType,
      testIds: form.value.testIds,
      description: form.value.description,
      enabled: form.value.enabled,
    };

    if (isCreating.value) {
      const response = await axios.post('/api/v1/test-suites', payload);
      const newSuiteId = response.data.id || response.data._id;
      await router.push({ name: 'TestSuiteDetail', params: { id: newSuiteId } });
      return;
    }

    await axios.put(`/api/v1/test-suites/${suiteId.value}`, payload);
    await loadSuite();
  } catch (err) {
    const axiosError = err as AxiosError;
    error.value = (axiosError.response?.data as { message?: string })?.message || 'Failed to save test suite';
    console.error('Error saving test suite:', axiosError);
    alert(error.value);
  } finally {
    saving.value = false;
  }
};

const runSuite = () => {
  alert('Test suite execution not yet implemented');
};

const goBack = () => {
  router.push('/tests');
};

watch(isCreating, (creating) => {
  if (!creating) {
    activeTab.value = 'overview';
  }
}, { immediate: true });

onMounted(() => {
  loadSuite();
});
</script>

<style scoped>
.test-suite-detail-page {
  padding: var(--spacing-lg);
  max-width: 1400px;
  margin: 0 auto;
}

.loading-state,
.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-2xl);
  text-align: center;
}

.detail-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
  margin-top: var(--spacing-md);
}

.header-left {
  flex: 1;
}

.suite-title-row {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-sm);
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0;
}

.suite-badges {
  display: flex;
  gap: var(--spacing-xs);
  align-items: center;
}

.suite-meta {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0;
}

.source-path {
  font-family: monospace;
  font-size: var(--font-size-sm);
}

.suite-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0 0 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-shrink: 0;
}

.creation-guide {
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.guide-content {
  display: flex;
  gap: var(--spacing-md);
}

.guide-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.guide-text h3 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.guide-text p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-sm) 0;
}

.guide-steps {
  margin: var(--spacing-md) 0 0 0;
  padding-left: var(--spacing-lg);
  color: var(--color-text-secondary);
}

.guide-steps li {
  margin-bottom: var(--spacing-xs);
}

.tab-content-container {
  margin-top: var(--spacing-lg);
}

.creation-layout {
  margin-top: 0;
}

.info-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
}

.info-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
}

.modal-help {
  margin-bottom: var(--spacing-md);
  color: var(--color-text-secondary);
}

.tests-selector {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  max-height: 400px;
  overflow-y: auto;
}

.test-option {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  cursor: pointer;
  transition: var(--transition-all);
}

.test-option:hover {
  border-color: var(--border-color-primary-active);
  background: var(--border-color-muted);
  opacity: 0.5;
}

.test-option.selected {
  border-color: var(--color-primary);
  background: var(--border-color-muted);
}

.test-option input[type="checkbox"] {
  margin-top: 2px;
  cursor: pointer;
}

.test-option-info {
  flex: 1;
}

.test-option-name-row {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.test-option-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.test-option-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}
</style>
