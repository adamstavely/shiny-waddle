<template>
  <div class="test-create-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div class="header-left">
          <h1 class="page-title">{{ isEditMode ? 'Edit Test' : 'Create Test' }}</h1>
          <p class="page-description">Create or edit individual reusable tests that can be assigned to test suites</p>
        </div>
        <div class="header-actions">
          <BaseButton
            :label="saving ? 'Saving...' : (isEditMode ? 'Update Test' : 'Create Test')"
            :icon="Save"
            @click="save"
            :disabled="saving"
          />
          <BaseButton label="Cancel" :icon="ArrowLeft" variant="ghost" @click="goBack" />
        </div>
      </div>
    </div>

    <div class="form-container">
      <BaseForm @submit="save" @cancel="goBack">
        <!-- Basic Information -->
        <div class="form-section form-section-full">
          <h3 class="section-title">Basic Information</h3>
          <div class="form-grid">
            <div class="form-group">
              <label>Test Name *</label>
              <input v-model="form.name" type="text" required class="form-input" />
            </div>
            <div class="form-group">
              <label>Test Category *</label>
              <Dropdown
                v-model="selectedCategory"
                :options="categoryOptions"
                placeholder="Select a category..."
                :disabled="isEditMode"
                required
                @change="handleCategoryChange"
              />
            </div>
            <div class="form-group">
              <label>Test Type *</label>
              <Dropdown
                v-model="form.testType"
                :options="filteredTestTypeOptions"
                placeholder="Select a test type..."
                :disabled="isEditMode || !selectedCategory"
                required
                @change="handleTestTypeChange"
              />
              <p v-if="isEditMode" class="field-help">Test type cannot be changed after creation</p>
            </div>
            <div v-if="isEditMode && test" class="form-group">
              <label>Current Version</label>
              <StatusBadge :status="`v${test.version}`" />
            </div>
          </div>
          <div class="form-group">
            <label>Description</label>
            <textarea v-model="form.description" rows="3" class="form-input"></textarea>
          </div>
          <div v-if="isEditMode" class="form-group">
            <label>Change Reason (optional)</label>
            <input v-model="form.changeReason" type="text" placeholder="Describe what changed..." class="form-input" />
          </div>
        </div>

        <!-- Test Type Specific Configuration -->
        <component
          :is="testTypeFormComponent"
          v-if="form.testType && testTypeFormComponent"
          :form="form"
          :is-edit-mode="isEditMode"
        />
        <div v-else-if="form.testType && !testTypeFormComponent" class="form-section form-section-full">
          <div class="info-message">
            <p><strong>Test type "{{ getTestTypeLabel(form.testType) }}" selected</strong></p>
            <p>Form configuration for this test type is coming soon. You can still create the test, but type-specific configuration will need to be added via API or JSON.</p>
          </div>
        </div>

        <!-- Validation Errors -->
        <div v-if="validationErrors.length > 0" class="validation-errors">
          <AlertTriangle class="error-icon" />
          <div>
            <strong>Please fix the following errors:</strong>
            <ul>
              <li v-for="(error, index) in validationErrors" :key="index">{{ error }}</li>
            </ul>
          </div>
        </div>
      </BaseForm>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Save, ArrowLeft, AlertTriangle } from 'lucide-vue-next';
import axios, { type AxiosError } from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import BaseForm from '../components/BaseForm.vue';
import BaseButton from '../components/BaseButton.vue';
import StatusBadge from '../components/StatusBadge.vue';
import Dropdown from '../components/Dropdown.vue';
import AccessControlTestForm from './tests/forms/AccessControlTestForm.vue';
import DLPTestForm from './tests/forms/DLPTestForm.vue';
import NetworkPolicyTestForm from './tests/forms/NetworkPolicyTestForm.vue';
import APISecurityTestForm from './tests/forms/APISecurityTestForm.vue';
import DistributedSystemsTestForm from './tests/forms/DistributedSystemsTestForm.vue';
import DataPipelineTestForm from './tests/forms/DataPipelineTestForm.vue';
import type { Test } from '../types/test';

const route = useRoute();
const router = useRouter();

const testId = computed(() => route.params.id as string);
const isEditMode = computed(() => !!testId.value);

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: isEditMode.value ? 'Edit Test' : 'Create Test' },
]);

const test = ref<Test | null>(null);
const loading = ref(false);
const saving = ref(false);
const validationErrors = ref<string[]>([]);
const selectedCategory = ref<string>('');

const form = ref<Partial<Test>>({
  name: '',
  description: '',
  testType: '',
  changeReason: '',
  // Access Control
  policyId: '',
  inputs: {
    subject: {
      role: '',
      attributes: {}
    },
    resource: { id: '', type: '', sensitivity: '' },
    context: { ipAddress: '', timeOfDay: '', location: '' }
  },
  expected: {
    allowed: true,
    reason: ''
  },
  // DLP
  pattern: { name: '', type: '', pattern: '' },
  expectedDetection: '',
  bulkExportType: '',
  bulkExportLimit: 0,
  testRecordCount: 0,
  expectedBlocked: '',
  exportRestrictions: { restrictedFields: [], requireMasking: false, allowedFormats: [] },
  aggregationRequirements: { minK: 0, requireAggregation: false },
  fieldRestrictions: { disallowedFields: [], allowedFields: [] },
  joinRestrictions: { disallowedJoins: [] },
  rlsCls: {
    database: { type: '', host: '', port: undefined, database: '', username: '', password: '', connectionString: '' },
    testQueries: [],
    maskingRules: [],
    validationRules: { minRLSCoverage: 0, minCLSCoverage: 0, requiredPolicies: [] }
  },
  // Distributed Systems
  applicationId: '',
  distributedTestType: undefined as 'multi-region' | 'policy-consistency' | 'policy-synchronization' | undefined,
  multiRegionConfig: {
    regions: [] as string[],
    executionMode: 'parallel' as 'parallel' | 'sequential',
    timeout: 30000,
    user: { id: '' },
    resource: { id: '' },
    action: 'read',
    expectedResult: undefined as boolean | undefined,
  },
  policyConsistencyConfig: {
    regions: [] as string[],
    policyIds: undefined as string[] | undefined,
    checkTypes: ['version', 'configuration'] as ('version' | 'configuration' | 'evaluation')[],
  },
  policySyncConfig: {
    regions: [] as string[],
    policyId: undefined as string | undefined,
    testScenarios: ['update-propagation', 'sync-timing'] as ('update-propagation' | 'sync-timing' | 'sync-failure-recovery')[],
  },
  // API Security
  apiVersion: { version: '', endpoint: '', deprecated: false, deprecationDate: '', sunsetDate: '' },
  gatewayPolicy: { gatewayType: '', endpoint: '', method: '', policyId: '', policyType: '' },
  webhook: {
    endpoint: '',
    authentication: { type: '', method: '', credentials: '' },
    rateLimiting: { enabled: false, maxRequests: 0, windowSeconds: 0 }
  },
  graphql: { endpoint: '', schema: '', testType: '', maxDepth: 0, maxComplexity: 0, introspectionEnabled: false },
  apiContract: { version: '', schemaText: '', schemaFormat: '' },
  // Network Policy
  networkPolicy: { source: '', target: '', protocol: '', port: undefined, action: '' },
  // Distributed Systems
  distributedSystems: {
    testType: '',
    regions: [],
    coordination: { type: '', endpoint: '' },
    policySync: { consistencyLevel: '' }
  },
  // Data Pipeline
  dataPipeline: {
    pipelineType: '',
    stage: '',
    action: '',
    expectedAccess: undefined,
    securityControls: { encryption: false, accessControl: false, auditLogging: false }
  }
});

const testTypeOptions = {
  'Access & Security': [
    { label: 'Access Control', value: 'access-control' },
    { label: 'Network Policy', value: 'network-policy' },
    { label: 'Data Loss Prevention (DLP)', value: 'dlp' },
    { label: 'API Security', value: 'api-security' },
    { label: 'API Gateway', value: 'api-gateway' },
    { label: 'RLS/CLS', value: 'rls-cls' },
  ],
  'Platform Configuration': [
    { label: 'Salesforce Config', value: 'salesforce-config' },
    { label: 'Salesforce Security', value: 'salesforce-security' },
    { label: 'Salesforce Experience Cloud', value: 'salesforce-experience-cloud' },
    { label: 'Elastic Config', value: 'elastic-config' },
    { label: 'Elastic Security', value: 'elastic-security' },
    { label: 'Kubernetes Security', value: 'k8s-security' },
    { label: 'Kubernetes Workload', value: 'k8s-workload' },
    { label: 'IDP Compliance', value: 'idp-compliance' },
    { label: 'ServiceNow Config', value: 'servicenow-config' },
  ],
  'Distributed Systems': [
    { label: 'Multi-Region', value: 'distributed-systems:multi-region' },
    { label: 'Policy Consistency', value: 'distributed-systems:policy-consistency' },
    { label: 'Policy Synchronization', value: 'distributed-systems:policy-synchronization' },
  ],
  'Data & Systems': [
    { label: 'Data Pipeline', value: 'data-pipeline' },
    { label: 'Data Contract', value: 'data-contract' },
    { label: 'Dataset Health', value: 'dataset-health' },
  ],
  'Environment Configuration': [
    { label: 'Environment Config', value: 'environment-config' },
    { label: 'Secrets Management', value: 'secrets-management' },
    { label: 'Configuration Drift', value: 'config-drift' },
    { label: 'Environment Policies', value: 'environment-policies' },
  ],
};

const categoryOptions = [
  { label: 'Access & Security', value: 'Access & Security' },
  { label: 'Platform Configuration', value: 'Platform Configuration' },
  { label: 'Distributed Systems', value: 'Distributed Systems' },
  { label: 'Data & Systems', value: 'Data & Systems' },
  { label: 'Environment Configuration', value: 'Environment Configuration' },
];

const filteredTestTypeOptions = computed(() => {
  if (!selectedCategory.value) {
    return [];
  }
  return testTypeOptions[selectedCategory.value as keyof typeof testTypeOptions] || [];
});

const handleCategoryChange = () => {
  // Reset test type when category changes
  form.value.testType = '';
  form.value.distributedTestType = undefined;
};

const handleTestTypeChange = () => {
  // For distributed systems, parse the value to extract testType and distributedTestType
  if (typeof form.value.testType === 'string' && form.value.testType.startsWith('distributed-systems:')) {
    const parts = form.value.testType.split(':');
    form.value.testType = 'distributed-systems';
    form.value.distributedTestType = parts[1] as 'multi-region' | 'policy-consistency' | 'policy-synchronization';
  } else {
    // For other test types, ensure distributedTestType is cleared
    if (form.value.testType !== 'distributed-systems') {
      form.value.distributedTestType = undefined;
    }
  }
};

const testTypeFormComponent = computed(() => {
  // Parse testType if it's a composite value
  const actualTestType = typeof form.value.testType === 'string' && form.value.testType.startsWith('distributed-systems:')
    ? 'distributed-systems'
    : form.value.testType;
    
  switch (actualTestType) {
    case 'access-control':
      return AccessControlTestForm;
    case 'dlp':
      return DLPTestForm;
    case 'network-policy':
      return NetworkPolicyTestForm;
    case 'api-security':
      return APISecurityTestForm;
    case 'distributed-systems':
      return DistributedSystemsTestForm;
    case 'data-pipeline':
      return DataPipelineTestForm;
    // Platform Configuration types - form components to be implemented
    case 'salesforce-config':
    case 'salesforce-security':
    case 'salesforce-experience-cloud':
    case 'elastic-config':
    case 'elastic-security':
    case 'k8s-security':
    case 'k8s-workload':
    case 'idp-compliance':
    case 'servicenow-config':
    // Data & Systems types - form components to be implemented
    case 'data-contract':
    case 'dataset-health':
    case 'rls-cls':
    case 'api-gateway':
    // Environment Configuration types - form components to be implemented
    case 'environment-config':
    case 'secrets-management':
    case 'config-drift':
    case 'environment-policies':
      // Return null for now - form components will be added later
      return null;
    default:
      return null;
  }
});

const getTestTypeLabel = (testType: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'api-gateway': 'API Gateway',
    'rls-cls': 'RLS/CLS',
    'data-pipeline': 'Data Pipeline',
    'data-contract': 'Data Contract',
    'dataset-health': 'Dataset Health',
    'salesforce-config': 'Salesforce Config',
    'salesforce-security': 'Salesforce Security',
    'salesforce-experience-cloud': 'Salesforce Experience Cloud',
    'elastic-config': 'Elastic Config',
    'elastic-security': 'Elastic Security',
    'k8s-security': 'Kubernetes Security',
    'k8s-workload': 'Kubernetes Workload',
    'idp-compliance': 'IDP Compliance',
    'servicenow-config': 'ServiceNow Config',
    'environment-config': 'Environment Config',
    'secrets-management': 'Secrets Management',
    'config-drift': 'Configuration Drift',
    'environment-policies': 'Environment Policies',
  };
  return labels[testType] || testType;
};

const handleFormUpdate = (updatedForm: Partial<Test>) => {
  form.value = { ...form.value, ...updatedForm };
};

const validate = (): boolean => {
  validationErrors.value = [];
  
  if (!form.value.name) {
    validationErrors.value.push('Test name is required');
  }
  
  if (!selectedCategory.value) {
    validationErrors.value.push('Test category is required');
  }
  
  if (!form.value.testType) {
    validationErrors.value.push('Test type is required');
  }
  
  // Type-specific validation would be handled by the form components
  // For now, basic validation for access-control
  if (form.value.testType === 'access-control') {
    if (!form.value.policyId) {
      validationErrors.value.push('A policy must be selected');
    }
  }
  
  // Validation for distributed-systems tests
  const actualTestType = typeof form.value.testType === 'string' && form.value.testType.startsWith('distributed-systems:') 
    ? 'distributed-systems' 
    : form.value.testType;
    
  if (actualTestType === 'distributed-systems') {
    if (!form.value.applicationId) {
      validationErrors.value.push('An application with distributed systems infrastructure must be selected');
    }
    if (!form.value.distributedTestType) {
      validationErrors.value.push('Distributed test type must be selected');
    }
    if (form.value.distributedTestType === 'multi-region') {
      if (!form.value.multiRegionConfig?.regions || form.value.multiRegionConfig.regions.length === 0) {
        validationErrors.value.push('At least one region must be selected for multi-region tests');
      }
    }
    if (form.value.distributedTestType === 'policy-consistency') {
      if (!form.value.policyConsistencyConfig?.regions || form.value.policyConsistencyConfig.regions.length < 2) {
        validationErrors.value.push('At least 2 regions must be selected for policy consistency tests');
      }
      if (!form.value.policyConsistencyConfig?.checkTypes || form.value.policyConsistencyConfig.checkTypes.length === 0) {
        validationErrors.value.push('At least one check type must be selected');
      }
    }
    if (form.value.distributedTestType === 'policy-synchronization') {
      if (!form.value.policySyncConfig?.regions || form.value.policySyncConfig.regions.length < 2) {
        validationErrors.value.push('At least 2 regions must be selected for policy synchronization tests');
      }
      if (!form.value.policySyncConfig?.testScenarios || form.value.policySyncConfig.testScenarios.length === 0) {
        validationErrors.value.push('At least one test scenario must be selected');
      }
    }
    if (!form.value.inputs?.resource?.id || !form.value.inputs?.resource?.type) {
      validationErrors.value.push('Resource ID and type are required');
    }
    if (form.value.expected === undefined) {
      validationErrors.value.push('Expected decision is required');
    }
  }
  
  return validationErrors.value.length === 0;
};

const getCategoryForTestType = (testType: string, distributedTestType?: string): string => {
  // Handle distributed systems specially
  if (testType === 'distributed-systems') {
    return 'Distributed Systems';
  }
  
  for (const [category, types] of Object.entries(testTypeOptions)) {
    if (types.some(t => {
      // Handle distributed systems composite values
      if (t.value.startsWith('distributed-systems:')) {
        return testType === 'distributed-systems' && 
               distributedTestType && 
               t.value === `distributed-systems:${distributedTestType}`;
      }
      return t.value === testType;
    })) {
      return category;
    }
  }
  return '';
};

const loadTest = async () => {
  if (!testId.value) return;
  
  loading.value = true;
  try {
    const response = await axios.get(`/api/tests/${testId.value}`);
    test.value = response.data;
    
    form.value.name = test.value.name;
    form.value.description = test.value.description || '';
    form.value.testType = test.value.testType;
    
    // Set category based on test type
    selectedCategory.value = getCategoryForTestType(test.value.testType, test.value.distributedTestType);
    
    // Set test type value (may need to be composite for distributed systems)
    if (test.value.testType === 'distributed-systems' && test.value.distributedTestType) {
      form.value.testType = `distributed-systems:${test.value.distributedTestType}` as any;
    } else {
      form.value.testType = test.value.testType;
    }
    
    // Load test-type-specific data
    if (test.value.testType === 'access-control') {
      form.value.policyId = test.value.policyId || '';
      form.value.inputs = test.value.inputs || {
        subject: { role: '', attributes: {} },
        resource: { id: '', type: '' },
        context: {}
      };
      form.value.expected = test.value.expected || { allowed: true };
    }
    // Other test types would be loaded here
  } catch (err: any) {
    console.error('Error loading test:', err);
    validationErrors.value.push(err.response?.data?.message || 'Failed to load test');
  } finally {
    loading.value = false;
  }
};

const save = async () => {
  if (!validate()) {
    return;
  }
  
  saving.value = true;
  try {
    // Parse testType if it's a composite value (for distributed systems)
    let actualTestType = form.value.testType;
    if (typeof form.value.testType === 'string' && form.value.testType.startsWith('distributed-systems:')) {
      actualTestType = 'distributed-systems';
    }
    
    const payload: Partial<Test> = {
      name: form.value.name,
      description: form.value.description,
      testType: actualTestType as any,
    };
    
    // Add test-type-specific payload
    if (actualTestType === 'access-control') {
      payload.policyId = form.value.policyId;
      payload.inputs = form.value.inputs;
      payload.expected = form.value.expected;
    } else if (actualTestType === 'distributed-systems') {
      payload.applicationId = form.value.applicationId;
      payload.distributedTestType = form.value.distributedTestType;
      payload.multiRegionConfig = form.value.multiRegionConfig;
      payload.policyConsistencyConfig = form.value.policyConsistencyConfig;
      payload.policySyncConfig = form.value.policySyncConfig;
    }
    // Other test types would be added here
    
    if (isEditMode.value) {
      await axios.patch(`/api/tests/${testId.value}`, payload);
    } else {
      await axios.post('/api/tests', payload);
    }
    
    router.push('/tests/individual');
  } catch (err: any) {
    validationErrors.value.push(err.response?.data?.message || 'Failed to save test');
    console.error('Error saving test:', err);
  } finally {
    saving.value = false;
  }
};

const goBack = () => {
  router.push('/tests/individual');
};

onMounted(() => {
  if (isEditMode.value) {
    loadTest();
  }
});
</script>

<style scoped>
.test-create-page {
  padding: var(--spacing-lg);
  max-width: 1400px;
  margin: 0 auto;
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

.header-left {
  flex: 1;
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-shrink: 0;
}

.form-container {
  margin-top: var(--spacing-lg);
}

.form-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
}

.form-section-full {
  width: 100%;
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-input {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.field-help {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin: var(--spacing-xs) 0 0 0;
}

.validation-errors {
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  display: flex;
  gap: var(--spacing-sm);
  color: var(--color-error);
  margin-top: var(--spacing-lg);
}

.validation-errors ul {
  margin: var(--spacing-xs) 0 0 0;
  padding-left: var(--spacing-lg);
}

.error-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.info-message {
  background: var(--color-info-bg);
  border: var(--border-width-thin) solid var(--color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  color: var(--color-text-primary);
}

.info-message p {
  margin: 0 0 var(--spacing-sm) 0;
}

.info-message p:last-child {
  margin-bottom: 0;
}
</style>
