<template>
  <div class="access-control-test-form">
    <h3 class="section-title">Access Control Configuration</h3>
    
    <!-- Policy Selection -->
    <div class="form-group">
      <label>Policies to Test *</label>
      <p class="form-help">Select one or more policies to test against</p>
      <div class="policy-selector">
        <div class="policy-filters">
          <Dropdown
            v-model="policyFilter"
            :options="[
              { label: 'All Policies', value: '' },
              { label: 'RBAC Only', value: 'rbac' },
              { label: 'ABAC Only', value: 'abac' }
            ]"
            placeholder="Filter policies..."
            class="form-input"
          />
        </div>
        <div v-if="loadingPolicies" class="loading-state">Loading policies...</div>
        <div v-else class="policies-list">
          <div
            v-for="policy in filteredPolicies"
            :key="policy.id"
            class="policy-option"
            :class="{ selected: form.policyIds?.includes(policy.id) }"
            @click="togglePolicy(policy.id)"
          >
            <input
              type="checkbox"
              :checked="form.policyIds?.includes(policy.id)"
              @change="togglePolicy(policy.id)"
            />
            <div class="policy-info">
              <div class="policy-name-row">
                <span class="policy-name">{{ policy.name }}</span>
                <StatusBadge :status="policy.type" :label="policy.type.toUpperCase()" size="sm" />
              </div>
              <p v-if="policy.description" class="policy-description">{{ policy.description }}</p>
            </div>
          </div>
        </div>
        <EmptyState
          v-if="!loading && filteredPolicies.length === 0"
          title="No policies found"
          description="Create a policy first"
          :show-default-action="false"
        >
          <template #actions>
            <router-link to="/policies">
              <BaseButton label="Create Policy" />
            </router-link>
          </template>
        </EmptyState>
      </div>
    </div>

    <!-- Role -->
    <div class="form-group">
      <label>Role *</label>
      <Dropdown
        v-model="form.role"
        :options="roleOptions"
        placeholder="Select a role..."
        required
        class="form-input"
      />
    </div>

    <!-- Resource -->
    <div class="form-group">
      <label>Resource *</label>
      <div class="resource-config">
        <div class="form-grid">
          <div class="form-group">
            <label>Resource ID</label>
            <input v-model="form.resource!.id" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Resource Type</label>
            <input v-model="form.resource!.type" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Sensitivity</label>
            <Dropdown
              v-model="form.resource!.sensitivity"
              :options="sensitivityOptions"
              placeholder="Select sensitivity..."
              class="form-input"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- Context -->
    <div class="form-group">
      <label>Context (optional)</label>
      <div class="context-config">
        <div class="form-grid">
          <div class="form-group">
            <label>IP Address</label>
            <input v-model="form.context!.ipAddress" type="text" class="form-input" />
          </div>
          <div class="form-group">
            <label>Time of Day</label>
            <input v-model="form.context!.timeOfDay" type="text" class="form-input" />
          </div>
          <div class="form-group">
            <label>Location</label>
            <input v-model="form.context!.location" type="text" class="form-input" />
          </div>
        </div>
      </div>
    </div>

    <!-- Expected Decision -->
    <div class="form-group">
      <label>Expected Decision *</label>
      <Dropdown
        v-model="form.expectedDecision"
        :options="expectedDecisionOptions"
        placeholder="Select expected decision..."
        required
        class="form-input"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import Dropdown from '../../../components/Dropdown.vue';
import StatusBadge from '../../../components/StatusBadge.vue';
import EmptyState from '../../../components/EmptyState.vue';
import BaseButton from '../../../components/BaseButton.vue';
import axios from 'axios';

interface Props {
  form: {
    policyIds: string[];
    role: string;
    resource: {
      id: string;
      type: string;
      sensitivity: string;
    };
    context: {
      ipAddress: string;
      timeOfDay: string;
      location: string;
    };
    expectedDecision: string;
  };
  loading?: boolean;
}

const props = defineProps<Props>();

defineEmits<{
  'update:form': [form: Props['form']];
}>();

const policyFilter = ref('');
const policies = ref<any[]>([]);
const loading = ref(false);

const filteredPolicies = computed(() => {
  let filtered = policies.value;
  if (policyFilter.value === 'rbac') {
    filtered = filtered.filter(p => p.type === 'rbac');
  } else if (policyFilter.value === 'abac') {
    filtered = filtered.filter(p => p.type === 'abac');
  }
  return filtered;
});

const roleOptions = computed(() => [
  { label: 'Admin', value: 'admin' },
  { label: 'User', value: 'user' },
  { label: 'Guest', value: 'guest' },
  { label: 'Viewer', value: 'viewer' }
]);

const sensitivityOptions = computed(() => [
  { label: 'Public', value: 'public' },
  { label: 'Internal', value: 'internal' },
  { label: 'Confidential', value: 'confidential' },
  { label: 'Restricted', value: 'restricted' }
]);

const expectedDecisionOptions = computed(() => [
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' }
]);

const togglePolicy = (policyId: string) => {
  if (!props.form.policyIds) {
    props.form.policyIds = [];
  }
  const index = props.form.policyIds.indexOf(policyId);
  if (index === -1) {
    props.form.policyIds.push(policyId);
  } else {
    props.form.policyIds.splice(index, 1);
  }
};

const loadPolicies = async () => {
  try {
    loadingPolicies.value = true;
    const response = await axios.get('/api/policies');
    policies.value = response.data as Policy[];
  } catch (err) {
    console.error('Error loading policies:', err);
  } finally {
    loadingPolicies.value = false;
  }
};

onMounted(() => {
  loadPolicies();
});
</script>

<style scoped>
.access-control-test-form {
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

.form-help {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin: 0 0 var(--spacing-sm) 0;
}

.policy-selector {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.policy-filters {
  margin-bottom: var(--spacing-sm);
}

.policies-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  max-height: 400px;
  overflow-y: auto;
}

.policy-option {
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

.policy-option:hover {
  border-color: var(--border-color-primary-active);
}

.policy-option.selected {
  border-color: var(--color-primary);
  background: rgba(79, 172, 254, 0.1);
}

.policy-option input[type="checkbox"] {
  margin-top: 2px;
  cursor: pointer;
}

.policy-info {
  flex: 1;
}

.policy-name-row {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.policy-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.policy-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.form-input {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.resource-config,
.context-config {
  margin-top: var(--spacing-sm);
}
</style>
