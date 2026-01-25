<template>
  <div class="distributed-systems-test-form">
    <h3 class="section-title">Distributed Systems Configuration</h3>
    
    <div class="form-group">
      <label>Test Type *</label>
      <Dropdown
        v-model="form.distributedSystems!.testType"
        :options="testTypeOptions"
        placeholder="Select test type..."
        required
        class="form-input"
      />
    </div>

    <div class="form-group">
      <label>Regions *</label>
      <p class="field-help">At least one region is required</p>
      <div v-for="(region, index) in form.distributedSystems!.regions" :key="index" class="region-item">
        <div class="form-grid">
          <div class="form-group">
            <label>Region ID</label>
            <input v-model="region.id" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Region Name</label>
            <input v-model="region.name" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Endpoint</label>
            <input v-model="region.endpoint" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>PDP Endpoint</label>
            <input v-model="region.pdpEndpoint" type="text" class="form-input" />
          </div>
        </div>
        <BaseButton label="Remove" variant="danger" size="sm" @click="removeRegion(index)" />
      </div>
      <BaseButton label="Add Region" variant="secondary" @click="addRegion" />
    </div>

    <div v-if="form.distributedSystems!.testType === 'synchronization' || form.distributedSystems!.testType === 'transaction'" class="form-section">
      <h4 class="subsection-title">Coordination</h4>
      <div class="form-grid">
        <div class="form-group">
          <label>Coordination Type *</label>
          <Dropdown
            v-model="form.distributedSystems!.coordination.type"
            :options="coordinationTypeOptions"
            placeholder="Select coordination type..."
            required
            class="form-input"
          />
        </div>
        <div class="form-group">
          <label>Coordination Endpoint *</label>
          <input v-model="form.distributedSystems!.coordination.endpoint" type="text" required class="form-input" />
        </div>
      </div>
    </div>

    <div v-if="form.distributedSystems!.testType === 'eventual-consistency'" class="form-section">
      <h4 class="subsection-title">Policy Sync</h4>
      <div class="form-group">
        <label>Consistency Level *</label>
        <Dropdown
          v-model="form.distributedSystems!.policySync.consistencyLevel"
          :options="consistencyLevelOptions"
          placeholder="Select consistency level..."
          required
          class="form-input"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import BaseButton from '../../../components/BaseButton.vue';
import Dropdown from '../../../components/Dropdown.vue';
import type { Test, Region } from '../../../types/test';

interface Props {
  form: Partial<Test>;
  isEditMode?: boolean;
}

const props = defineProps<Props>();

defineEmits<{
  'update:form': [form: Partial<Test>];
}>();

const testTypeOptions = [
  { label: 'Policy Consistency', value: 'policy-consistency' },
  { label: 'Eventual Consistency', value: 'eventual-consistency' },
  { label: 'Synchronization', value: 'synchronization' },
  { label: 'Transaction', value: 'transaction' },
];

const coordinationTypeOptions = [
  { label: 'Two-Phase Commit', value: '2pc' },
  { label: 'Saga', value: 'saga' },
  { label: 'Distributed Lock', value: 'lock' },
];

const consistencyLevelOptions = [
  { label: 'Strong', value: 'strong' },
  { label: 'Eventual', value: 'eventual' },
  { label: 'Weak', value: 'weak' },
];

const addRegion = () => {
  if (!props.form.distributedSystems) {
    props.form.distributedSystems = {
      testType: '',
      regions: [],
      coordination: { type: '', endpoint: '' },
      policySync: { consistencyLevel: '' }
    };
  }
  props.form.distributedSystems.regions.push({ id: '', name: '', endpoint: '', pdpEndpoint: undefined });
};

const removeRegion = (index: number) => {
  if (props.form.distributedSystems?.regions) {
    props.form.distributedSystems.regions.splice(index, 1);
  }
};

// Initialize distributedSystems if not present
if (!props.form.distributedSystems) {
  props.form.distributedSystems = {
    testType: '',
    regions: [],
    coordination: { type: '', endpoint: '' },
    policySync: { consistencyLevel: '' }
  };
}
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
  color: var(--color-text-muted);
  margin: var(--spacing-xs) 0 0 0;
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
  margin-bottom: var(--spacing-lg);
}

.region-item {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-sm);
}
</style>
