<template>
  <div class="distributed-systems-test-form">
    <h3 class="section-title">Distributed Systems Configuration</h3>
    
    <!-- Application Selection -->
    <div class="form-group">
      <label>Application *</label>
      <p class="field-help">Select an application with distributed systems infrastructure configured</p>
      <Dropdown
        v-model="form.applicationId"
        :options="applicationOptions"
        placeholder="Select application..."
        required
        class="form-input"
        :loading="loadingApplications"
        @change="handleApplicationChange"
      />
      <div v-if="selectedApplication && !hasDistributedSystems" class="error-message">
        Selected application does not have distributed systems infrastructure configured.
      </div>
    </div>

    <!-- Distributed Test Type -->
    <div class="form-group">
      <label>Distributed Test Type *</label>
      <p class="field-help">Select the type of distributed systems test to run</p>
      <Dropdown
        v-model="form.distributedTestType"
        :options="distributedTestTypeOptions"
        placeholder="Select test type..."
        required
        class="form-input"
        :disabled="!form.applicationId || !hasDistributedSystems"
      />
    </div>

    <!-- Multi-Region Test Configuration -->
    <div v-if="form.distributedTestType === 'multi-region'" class="form-section">
      <h4 class="subsection-title">Multi-Region Test Configuration</h4>
      
      <div class="form-group">
        <label>Regions to Test *</label>
        <p class="field-help">Select at least one region to test</p>
        <div v-if="availableRegions.length > 0" class="region-checkboxes">
          <label
            v-for="region in availableRegions"
            :key="region.id"
            class="checkbox-label"
          >
            <input
              type="checkbox"
              :value="region.id"
              :checked="isRegionSelected(region.id)"
              @change="toggleRegion(region.id)"
            />
            <span>{{ region.name }} ({{ region.id }})</span>
          </label>
        </div>
        <div v-else class="info-message">
          No regions available. Please configure regions in the application infrastructure.
        </div>
      </div>

      <div class="form-group">
        <label>Execution Mode</label>
        <Dropdown
          v-model="form.multiRegionConfig.executionMode"
          :options="executionModeOptions"
          placeholder="Select execution mode..."
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label>Timeout (ms)</label>
        <input
          v-model.number="form.multiRegionConfig.timeout"
          type="number"
          placeholder="30000"
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label>User ID</label>
        <input
          v-model="form.multiRegionConfig.user.id"
          type="text"
          placeholder="user-123"
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label>Resource ID</label>
        <input
          v-model="form.multiRegionConfig.resource.id"
          type="text"
          placeholder="resource-456"
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label>Action</label>
        <input
          v-model="form.multiRegionConfig.action"
          type="text"
          placeholder="read"
          class="form-input"
        />
      </div>

      <div class="form-group">
        <label>Expected Result</label>
        <Dropdown
          v-model="form.multiRegionConfig.expectedResult"
          :options="expectedResultOptions"
          placeholder="Select expected result..."
          class="form-input"
        />
      </div>
    </div>

    <!-- Policy Consistency Test Configuration -->
    <div v-if="form.distributedTestType === 'policy-consistency'" class="form-section">
      <h4 class="subsection-title">Policy Consistency Test Configuration</h4>
      
      <div class="form-group">
        <label>Regions to Check *</label>
        <p class="field-help">Select at least 2 regions to check for consistency</p>
        <div v-if="availableRegions.length > 0" class="region-checkboxes">
          <label
            v-for="region in availableRegions"
            :key="region.id"
            class="checkbox-label"
          >
            <input
              type="checkbox"
              :value="region.id"
              :checked="isConsistencyRegionSelected(region.id)"
              @change="toggleConsistencyRegion(region.id)"
            />
            <span>{{ region.name }} ({{ region.id }})</span>
          </label>
        </div>
        <div v-else class="info-message">
          No regions available. Please configure regions in the application infrastructure.
        </div>
      </div>

      <div class="form-group">
        <label>Check Types *</label>
        <p class="field-help">Select at least one check type</p>
        <div class="region-checkboxes">
          <label class="checkbox-label">
            <input
              type="checkbox"
              value="version"
              :checked="form.policyConsistencyConfig.checkTypes.includes('version')"
              @change="toggleCheckType('version')"
            />
            <span>Version Consistency</span>
          </label>
          <label class="checkbox-label">
            <input
              type="checkbox"
              value="configuration"
              :checked="form.policyConsistencyConfig.checkTypes.includes('configuration')"
              @change="toggleCheckType('configuration')"
            />
            <span>Configuration Consistency</span>
          </label>
          <label class="checkbox-label">
            <input
              type="checkbox"
              value="evaluation"
              :checked="form.policyConsistencyConfig.checkTypes.includes('evaluation')"
              @change="toggleCheckType('evaluation')"
            />
            <span>Evaluation Consistency</span>
          </label>
        </div>
      </div>

      <div class="form-group">
        <label>Policy IDs (optional)</label>
        <p class="field-help">Leave empty to check all policies, or specify policy IDs separated by commas</p>
        <input
          v-model="policyIdsInput"
          type="text"
          placeholder="policy-1, policy-2"
          class="form-input"
          @blur="updatePolicyIds"
        />
      </div>
    </div>

    <!-- Policy Synchronization Test Configuration -->
    <div v-if="form.distributedTestType === 'policy-synchronization'" class="form-section">
      <h4 class="subsection-title">Policy Synchronization Test Configuration</h4>
      
      <div class="form-group">
        <label>Regions to Test *</label>
        <p class="field-help">Select at least 2 regions to test synchronization</p>
        <div v-if="availableRegions.length > 0" class="region-checkboxes">
          <label
            v-for="region in availableRegions"
            :key="region.id"
            class="checkbox-label"
          >
            <input
              type="checkbox"
              :value="region.id"
              :checked="isSyncRegionSelected(region.id)"
              @change="toggleSyncRegion(region.id)"
            />
            <span>{{ region.name }} ({{ region.id }})</span>
          </label>
        </div>
        <div v-else class="info-message">
          No regions available. Please configure regions in the application infrastructure.
        </div>
      </div>

      <div class="form-group">
        <label>Test Scenarios *</label>
        <p class="field-help">Select at least one test scenario</p>
        <div class="region-checkboxes">
          <label class="checkbox-label">
            <input
              type="checkbox"
              value="update-propagation"
              :checked="form.policySyncConfig.testScenarios.includes('update-propagation')"
              @change="toggleTestScenario('update-propagation')"
            />
            <span>Update Propagation</span>
          </label>
          <label class="checkbox-label">
            <input
              type="checkbox"
              value="sync-timing"
              :checked="form.policySyncConfig.testScenarios.includes('sync-timing')"
              @change="toggleTestScenario('sync-timing')"
            />
            <span>Sync Timing</span>
          </label>
          <label class="checkbox-label">
            <input
              type="checkbox"
              value="sync-failure-recovery"
              :checked="form.policySyncConfig.testScenarios.includes('sync-failure-recovery')"
              @change="toggleTestScenario('sync-failure-recovery')"
            />
            <span>Sync Failure Recovery</span>
          </label>
        </div>
      </div>

      <div class="form-group">
        <label>Policy ID (optional)</label>
        <p class="field-help">Leave empty to test all policies, or specify a specific policy ID</p>
        <input
          v-model="form.policySyncConfig.policyId"
          type="text"
          placeholder="policy-123"
          class="form-input"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import Dropdown from '../../../components/Dropdown.vue';
import type { Test } from '../../../types/test';
import axios from 'axios';

interface Props {
  form: Partial<Test>;
  isEditMode?: boolean;
}

const props = defineProps<Props>();

const loadingApplications = ref(false);
const applications = ref<any[]>([]);
const availableRegions = ref<any[]>([]);
const selectedApplication = ref<any>(null);
const policyIdsInput = ref('');

// Initialize form structure
if (!props.form.distributedTestType) {
  props.form.distributedTestType = undefined;
}

if (!props.form.multiRegionConfig) {
  props.form.multiRegionConfig = {
    regions: [],
    executionMode: 'parallel',
    timeout: 30000,
    user: { id: '' },
    resource: { id: '' },
    action: 'read',
    expectedResult: undefined,
  };
}

if (!props.form.policyConsistencyConfig) {
  props.form.policyConsistencyConfig = {
    regions: [],
    policyIds: undefined,
    checkTypes: ['version', 'configuration'],
  };
}

if (!props.form.policySyncConfig) {
  props.form.policySyncConfig = {
    regions: [],
    policyId: undefined,
    testScenarios: ['update-propagation', 'sync-timing'],
  };
}

const distributedTestTypeOptions = [
  { label: 'Multi-Region Test', value: 'multi-region' },
  { label: 'Policy Consistency', value: 'policy-consistency' },
  { label: 'Policy Synchronization', value: 'policy-synchronization' },
];

const executionModeOptions = [
  { label: 'Parallel', value: 'parallel' },
  { label: 'Sequential', value: 'sequential' },
];

const expectedResultOptions = [
  { label: 'Allow', value: true },
  { label: 'Deny', value: false },
];

const applicationOptions = computed(() => {
  return applications.value.map(app => ({
    label: app.name,
    value: app.id,
  }));
});

const hasDistributedSystems = computed(() => {
  return selectedApplication.value?.infrastructure?.distributedSystems?.regions?.length > 0;
});

const isRegionSelected = (regionId: string): boolean => {
  return props.form.multiRegionConfig?.regions?.includes(regionId) || false;
};

const isConsistencyRegionSelected = (regionId: string): boolean => {
  return props.form.policyConsistencyConfig?.regions?.includes(regionId) || false;
};

const isSyncRegionSelected = (regionId: string): boolean => {
  return props.form.policySyncConfig?.regions?.includes(regionId) || false;
};

const toggleRegion = (regionId: string) => {
  if (!props.form.multiRegionConfig) {
    props.form.multiRegionConfig = { regions: [] };
  }
  const index = props.form.multiRegionConfig.regions?.indexOf(regionId) ?? -1;
  if (index === -1) {
    props.form.multiRegionConfig.regions = [...(props.form.multiRegionConfig.regions || []), regionId];
  } else {
    props.form.multiRegionConfig.regions = props.form.multiRegionConfig.regions?.filter(r => r !== regionId) || [];
  }
};

const toggleConsistencyRegion = (regionId: string) => {
  if (!props.form.policyConsistencyConfig) {
    props.form.policyConsistencyConfig = { regions: [], checkTypes: [] };
  }
  const index = props.form.policyConsistencyConfig.regions?.indexOf(regionId) ?? -1;
  if (index === -1) {
    props.form.policyConsistencyConfig.regions = [...(props.form.policyConsistencyConfig.regions || []), regionId];
  } else {
    props.form.policyConsistencyConfig.regions = props.form.policyConsistencyConfig.regions?.filter(r => r !== regionId) || [];
  }
};

const toggleSyncRegion = (regionId: string) => {
  if (!props.form.policySyncConfig) {
    props.form.policySyncConfig = { regions: [], testScenarios: [] };
  }
  const index = props.form.policySyncConfig.regions?.indexOf(regionId) ?? -1;
  if (index === -1) {
    props.form.policySyncConfig.regions = [...(props.form.policySyncConfig.regions || []), regionId];
  } else {
    props.form.policySyncConfig.regions = props.form.policySyncConfig.regions?.filter(r => r !== regionId) || [];
  }
};

const toggleCheckType = (checkType: 'version' | 'configuration' | 'evaluation') => {
  if (!props.form.policyConsistencyConfig) {
    props.form.policyConsistencyConfig = { regions: [], checkTypes: [] };
  }
  const index = props.form.policyConsistencyConfig.checkTypes?.indexOf(checkType) ?? -1;
  if (index === -1) {
    props.form.policyConsistencyConfig.checkTypes = [...(props.form.policyConsistencyConfig.checkTypes || []), checkType];
  } else {
    props.form.policyConsistencyConfig.checkTypes = props.form.policyConsistencyConfig.checkTypes?.filter(ct => ct !== checkType) || [];
  }
};

const toggleTestScenario = (scenario: 'update-propagation' | 'sync-timing' | 'sync-failure-recovery') => {
  if (!props.form.policySyncConfig) {
    props.form.policySyncConfig = { regions: [], testScenarios: [] };
  }
  const index = props.form.policySyncConfig.testScenarios?.indexOf(scenario) ?? -1;
  if (index === -1) {
    props.form.policySyncConfig.testScenarios = [...(props.form.policySyncConfig.testScenarios || []), scenario];
  } else {
    props.form.policySyncConfig.testScenarios = props.form.policySyncConfig.testScenarios?.filter(s => s !== scenario) || [];
  }
};

const updatePolicyIds = () => {
  if (!props.form.policyConsistencyConfig) {
    props.form.policyConsistencyConfig = { regions: [], checkTypes: [] };
  }
  if (policyIdsInput.value.trim()) {
    props.form.policyConsistencyConfig.policyIds = policyIdsInput.value
      .split(',')
      .map(id => id.trim())
      .filter(id => id.length > 0);
  } else {
    props.form.policyConsistencyConfig.policyIds = undefined;
  }
};

const loadApplications = async () => {
  loadingApplications.value = true;
  try {
    const response = await axios.get('/api/v1/applications');
    applications.value = response.data || [];
  } catch (error: any) {
    console.error('Failed to load applications:', error);
    applications.value = [];
  } finally {
    loadingApplications.value = false;
  }
};

const handleApplicationChange = async () => {
  if (!props.form.applicationId) {
    selectedApplication.value = null;
    availableRegions.value = [];
    return;
  }

  try {
    const response = await axios.get(`/api/v1/applications/${props.form.applicationId}`);
    selectedApplication.value = response.data;
    
    if (selectedApplication.value?.infrastructure?.distributedSystems?.regions) {
      availableRegions.value = selectedApplication.value.infrastructure.distributedSystems.regions;
      
      // Auto-select all regions for convenience
      if (props.form.distributedTestType === 'multi-region' && props.form.multiRegionConfig) {
        props.form.multiRegionConfig.regions = availableRegions.value.map((r: any) => r.id);
      } else if (props.form.distributedTestType === 'policy-consistency' && props.form.policyConsistencyConfig) {
        props.form.policyConsistencyConfig.regions = availableRegions.value.map((r: any) => r.id);
      } else if (props.form.distributedTestType === 'policy-synchronization' && props.form.policySyncConfig) {
        props.form.policySyncConfig.regions = availableRegions.value.map((r: any) => r.id);
      }
    } else {
      availableRegions.value = [];
    }
  } catch (error: any) {
    console.error('Failed to load application:', error);
    selectedApplication.value = null;
    availableRegions.value = [];
  }
};

// Watch for distributedTestType changes to reset configs
watch(() => props.form.distributedTestType, (newType) => {
  if (newType === 'multi-region' && availableRegions.value.length > 0) {
    if (props.form.multiRegionConfig) {
      props.form.multiRegionConfig.regions = availableRegions.value.map((r: any) => r.id);
    }
  } else if (newType === 'policy-consistency' && availableRegions.value.length > 0) {
    if (props.form.policyConsistencyConfig) {
      props.form.policyConsistencyConfig.regions = availableRegions.value.map((r: any) => r.id);
    }
  } else if (newType === 'policy-synchronization' && availableRegions.value.length > 0) {
    if (props.form.policySyncConfig) {
      props.form.policySyncConfig.regions = availableRegions.value.map((r: any) => r.id);
    }
  }
});

onMounted(() => {
  loadApplications();
  
  // If editing and applicationId exists, load regions
  if (props.form.applicationId) {
    handleApplicationChange();
  }
  
  // Initialize policyIdsInput if editing
  if (props.form.policyConsistencyConfig?.policyIds) {
    policyIdsInput.value = props.form.policyConsistencyConfig.policyIds.join(', ');
  }
});
</script>

<style scoped>
.distributed-systems-test-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
}

.subsection-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: var(--spacing-md) 0 var(--spacing-sm) 0;
}

.form-section {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  margin-bottom: var(--spacing-md);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.field-help {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0 0 0;
}

.form-input {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.form-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.region-checkboxes {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  max-height: 300px;
  overflow-y: auto;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-weight: normal;
  color: var(--color-text-secondary);
  cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
  width: auto;
  margin: 0;
  cursor: pointer;
}

.error-message {
  color: #ef4444;
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-xs);
}

.info-message {
  padding: var(--spacing-md);
  background: rgba(79, 172, 254, 0.1);
  border: var(--border-width-thin) solid rgba(79, 172, 254, 0.2);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}
</style>
