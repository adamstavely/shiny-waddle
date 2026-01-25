<template>
  <div class="policy-detail-page">
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading policy...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <BaseButton label="Retry" @click="loadPolicy" />
    </div>
    <div v-else-if="policy" class="policy-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <div class="policy-title-row">
              <h1 class="page-title">{{ policy.name }}</h1>
              <StatusBadge :status="policy.status" />
            </div>
            <p class="policy-meta">
              {{ policy.type.toUpperCase() }} • v{{ policy.version }}
            </p>
            <p v-if="policy.description" class="policy-description">{{ policy.description }}</p>
          </div>
          <div class="header-actions">
            <BaseButton label="Edit" :icon="Edit" variant="secondary" @click="editPolicy" />
            <BaseButton label="Test" :icon="TestTube" variant="secondary" @click="testPolicy" />
            <BaseButton label="Versions" :icon="History" variant="ghost" @click="viewVersions" />
            <BaseButton label="Deploy" :icon="Upload" variant="secondary" @click="deployPolicy" />
            <BaseButton label="Audit Log" :icon="FileText" variant="ghost" @click="showAuditLog = true; loadAuditLogs()" />
          </div>
        </div>
      </div>

      <!-- Content Sections -->
      <div class="content-sections">
        <!-- Overview Section -->
        <PolicyOverviewSection :policy="policy" />

        <!-- Tests Using This Policy Section -->
        <PolicyTestsSection
          :tests="testsUsingPolicy"
          :loading="loadingTests"
          @create-test="createTestFromPolicy"
          @view-all-tests="viewAllTests"
          @view-test="viewTest"
        />

        <!-- Validators Using This Policy Section -->
        <div v-if="validatorsUsingPolicy.length > 0" class="content-section">
          <div class="section-header">
            <h2 class="section-title">
              <TestTube class="title-icon" />
              Validators Using This Policy
            </h2>
            <StatusBadge :status="`${validatorsUsingPolicy.length} validator${validatorsUsingPolicy.length !== 1 ? 's' : ''}`" size="sm" />
          </div>
          <div class="validators-list">
            <div
              v-for="validator in validatorsUsingPolicy"
              :key="validator.id"
              class="validator-item"
              @click="viewValidator(validator.id)"
            >
              <div class="validator-info">
                <h4 class="validator-name">{{ validator.name }}</h4>
                <p v-if="validator.description" class="validator-description">{{ validator.description }}</p>
                <div class="validator-meta">
                  <span class="meta-item">
                    <span class="meta-label">Type:</span>
                    <span class="meta-value">{{ validator.testType }}</span>
                  </span>
                  <span class="meta-item">
                    <span class="meta-label">Version:</span>
                    <span class="meta-value">{{ validator.version }}</span>
                  </span>
                  <span class="meta-item">
                    <StatusBadge :status="validator.enabled ? 'enabled' : 'disabled'" size="sm" />
                  </span>
                </div>
              </div>
              <div class="validator-actions">
                <BaseButton label="View Details" :icon="Eye" variant="ghost" size="sm" @click.stop="viewValidator(validator.id)" />
              </div>
            </div>
          </div>
        </div>

        <!-- Rules/Conditions Section -->
        <PolicyRulesSection :policy="policy" />

        <!-- JSON Section -->
        <PolicyJSONSection :policy-json="policyJSON" />

        <!-- Changelog Section -->
        <PolicyChangelogSection
          :versions="policy.versions || []"
          @add-version="showVersionModal = true"
        />
      </div>

      <!-- Modals -->
      <BaseModal
        :isOpen="showVersionModal"
        title="Add Version"
        :icon="History"
        @update:isOpen="showVersionModal = $event"
        @close="closeVersionModal"
      >
        <BaseForm @submit="addVersion" @cancel="closeVersionModal">
          <div class="form-group">
            <label>Version *</label>
            <input v-model="versionForm.version" type="text" required placeholder="e.g., 1.1.0" />
          </div>
          <div class="form-group">
            <label>Status</label>
            <Dropdown
              v-model="versionForm.status"
              :options="versionStatusOptions"
              placeholder="Select status..."
            />
          </div>
          <div class="form-group">
            <label>Notes</label>
            <textarea v-model="versionForm.notes" rows="3" placeholder="Version notes..."></textarea>
          </div>
          <div class="form-group">
            <label>Changes</label>
            <div
              v-for="(change, index) in versionForm.changes"
              :key="index"
              class="change-row"
            >
              <Dropdown
                v-model="change.type"
                :options="changeTypeOptions"
                placeholder="Change type..."
              />
              <input
                v-model="change.description"
                type="text"
                placeholder="Change description..."
              />
              <BaseButton label="Remove" variant="danger" size="sm" @click="removeChange(index)" />
            </div>
            <BaseButton label="Add Change" variant="secondary" size="sm" @click="addChange" />
          </div>
          <template #footer>
            <BaseButton label="Cancel" variant="secondary" @click="closeVersionModal" />
            <BaseButton label="Add Version" type="submit" />
          </template>
        </BaseForm>
      </BaseModal>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  Edit,
  TestTube,
  History,
  Upload,
  FileText,
  Eye
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import BaseButton from '../components/BaseButton.vue';
import BaseModal from '../components/BaseModal.vue';
import BaseForm from '../components/BaseForm.vue';
import StatusBadge from '../components/StatusBadge.vue';
import Dropdown from '../components/Dropdown.vue';
import PolicyOverviewSection from './policies/detail/PolicyOverviewSection.vue';
import PolicyRulesSection from './policies/detail/PolicyRulesSection.vue';
import PolicyTestsSection from './policies/detail/PolicyTestsSection.vue';
import PolicyJSONSection from './policies/detail/PolicyJSONSection.vue';
import PolicyChangelogSection from './policies/detail/PolicyChangelogSection.vue';
import type { Policy, Test, Validator } from '../types/test';
import type { AxiosError } from 'axios';
import type { Policy, Test, Validator } from '../types/test';

const route = useRoute();
const router = useRouter();

const policyId = computed(() => route.params.id as string);
const loading = ref(true);
const error = ref<string | null>(null);
const showVersionModal = ref(false);
const showAuditLog = ref(false);

const policy = ref<Policy | null>(null);
const validators = ref<Validator[]>([]);
const testsUsingPolicy = ref<Test[]>([]);
const loadingTests = ref(false);

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: policy.value?.name || 'Policy' }
]);

const validatorsUsingPolicy = computed(() => {
  if (!policy.value || validators.value.length === 0) return [];
  
  return validators.value.filter(validator => {
    if (policy.value.type === 'rbac' && validator.testType === 'access-control') {
      return true;
    }
    if (policy.value.type === 'abac' && validator.testType === 'access-control') {
      return true;
    }
    if (validator.config?.policyId === policy.value.id) {
      return true;
    }
    if (validator.config?.policies?.includes(policy.value.id)) {
      return true;
    }
    return false;
  });
});

const versionForm = ref({
  version: '',
  status: 'draft',
  changes: [{ type: 'added', description: '' }],
  notes: ''
});

const versionStatusOptions = computed(() => [
  { label: 'Draft', value: 'draft' },
  { label: 'Active', value: 'active' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const changeTypeOptions = computed(() => [
  { label: 'Added', value: 'added' },
  { label: 'Changed', value: 'changed' },
  { label: 'Fixed', value: 'fixed' },
  { label: 'Removed', value: 'removed' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const policyJSON = computed(() => {
  if (!policy.value) return {};
  
  if (policy.value.type === 'rbac') {
    return {
      name: policy.value.name,
      version: policy.value.version,
      rules: policy.value.rules
    };
  } else {
    return {
      id: policy.value.id,
      name: policy.value.name,
      description: policy.value.description,
      effect: policy.value.effect,
      priority: policy.value.priority,
      conditions: policy.value.conditions
    };
  }
});

const loadPolicy = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get(`/api/policies/${policyId.value}`);
    policy.value = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      lastUpdated: new Date(response.data.updatedAt),
      ruleCount: response.data.ruleCount || (response.data.type === 'rbac' 
        ? (response.data.rules?.length || 0) 
        : (response.data.conditions?.length || 0)),
      versions: (response.data.versions || []).map((v: Policy['versions'][0]) => ({
        ...v,
        date: new Date(v.date as string)
      }))
    };
    await loadTests();
    await loadValidators();
  } catch (err) {
    const axiosError = err as AxiosError;
    error.value = axiosError.message || 'Failed to load policy';
  } finally {
    loading.value = false;
  }
};

const loadTests = async () => {
  try {
    loadingTests.value = true;
    const response = await axios.get(`/api/v1/tests?policyIds=${policyId.value}`);
    testsUsingPolicy.value = response.data;
  } catch (err) {
    console.error('Error loading tests:', err);
    testsUsingPolicy.value = [];
  } finally {
    loadingTests.value = false;
  }
};

const loadValidators = async () => {
  try {
    const response = await axios.get('/api/validators');
    validators.value = response.data;
  } catch (err) {
    console.error('Error loading validators:', err);
  }
};

const loadAuditLogs = async () => {
  // Load audit logs
  console.log('Loading audit logs...');
};

const editPolicy = () => {
  router.push(`/policies/${policyId.value}/edit`);
};

const testPolicy = async () => {
  router.push(`/policies/${policyId.value}?tab=test`);
};

const viewVersions = () => {
  showVersionModal.value = true;
};

const viewTest = (testId: string) => {
  router.push(`/tests/individual/${testId}`);
};

const viewValidator = (validatorId: string) => {
  router.push(`/admin?tab=validators&validator=${validatorId}`);
};

const createTestFromPolicy = () => {
  router.push(`/tests/individual/new?policyId=${policyId.value}`);
};

const viewAllTests = () => {
  router.push(`/tests/individual?policyId=${policyId.value}`);
};

const addChange = () => {
  versionForm.value.changes.push({ type: 'added', description: '' });
};

const removeChange = (index: number) => {
  versionForm.value.changes.splice(index, 1);
};

const addVersion = async () => {
  if (!policy.value) return;
  
  try {
    loading.value = true;
    const newVersion = {
      version: versionForm.value.version,
      status: versionForm.value.status,
      date: new Date(),
      author: 'current-user@example.com',
      changes: versionForm.value.changes.filter(c => c.description),
      notes: versionForm.value.notes
    };
    
    await axios.post(`/api/policies/${policyId.value}/versions`, newVersion);
    await loadPolicy();
    closeVersionModal();
  } catch (err) {
    const axiosError = err as AxiosError;
    error.value = (axiosError.response?.data as { message?: string })?.message || axiosError.message || 'Failed to add version';
  } finally {
    loading.value = false;
  }
};

const deployPolicy = async () => {
  if (!confirm(`Deploy version ${policy.value?.version}?`)) {
    return;
  }
  
  try {
    loading.value = true;
    await axios.post(`/api/policies/${policyId.value}/deploy`);
    await loadPolicy();
  } catch (err) {
    const axiosError = err as AxiosError;
    error.value = (axiosError.response?.data as { message?: string })?.message || axiosError.message || 'Failed to deploy policy';
  } finally {
    loading.value = false;
  }
};

const closeVersionModal = () => {
  showVersionModal.value = false;
  versionForm.value = {
    version: '',
    status: 'draft',
    changes: [{ type: 'added', description: '' }],
    notes: ''
  };
};

onMounted(() => {
  loadPolicy();
});
</script>

<style scoped>
.policy-detail-page {
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

.policy-title-row {
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

.policy-meta {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0;
}

.policy-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0 0 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
  flex-shrink: 0;
}

.content-sections {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.content-section {
  margin-bottom: var(--spacing-xl);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.validators-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.validator-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  cursor: pointer;
  transition: var(--transition-all);
}

.validator-item:hover {
  border-color: var(--border-color-primary-active);
  background: rgba(79, 172, 254, 0.05);
}

.validator-info {
  flex: 1;
}

.validator-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.validator-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0 var(--spacing-sm) 0;
}

.validator-meta {
  display: flex;
  gap: var(--spacing-lg);
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
}

.meta-label {
  color: var(--color-text-secondary);
}

.meta-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.validator-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-shrink: 0;
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

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.change-row {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
  align-items: center;
}

.change-row input {
  flex: 1;
}
</style>
