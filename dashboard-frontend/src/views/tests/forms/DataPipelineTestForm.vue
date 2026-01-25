<template>
  <div class="data-pipeline-test-form">
    <h3 class="section-title">Data Pipeline Configuration</h3>
    
    <div class="form-grid">
      <div class="form-group">
        <label>Pipeline Type *</label>
        <Dropdown
          v-model="form.dataPipeline!.pipelineType"
          :options="pipelineTypeOptions"
          placeholder="Select pipeline type..."
          required
          class="form-input"
        />
      </div>
      <div class="form-group">
        <label>Stage *</label>
        <Dropdown
          v-model="form.dataPipeline!.stage"
          :options="stageOptions"
          placeholder="Select stage..."
          required
          class="form-input"
        />
      </div>
      <div class="form-group">
        <label>Action *</label>
        <Dropdown
          v-model="form.dataPipeline!.action"
          :options="actionOptions"
          placeholder="Select action..."
          required
          class="form-input"
        />
      </div>
    </div>

    <div class="form-group">
      <label>Expected Access *</label>
      <Dropdown
        v-model="form.dataPipeline!.expectedAccess"
        :options="expectedAccessOptions"
        placeholder="Select expected access..."
        required
        class="form-input"
      />
    </div>

    <div class="form-group">
      <label>Security Controls *</label>
      <p class="field-help">At least one security control must be selected</p>
      <div class="checkbox-group">
        <label>
          <input v-model="form.dataPipeline!.securityControls.encryption" type="checkbox" />
          Encryption
        </label>
        <label>
          <input v-model="form.dataPipeline!.securityControls.accessControl" type="checkbox" />
          Access Control
        </label>
        <label>
          <input v-model="form.dataPipeline!.securityControls.auditLogging" type="checkbox" />
          Audit Logging
        </label>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import Dropdown from '../../../components/Dropdown.vue';
import type { Test } from '../../../types/test';

interface Props {
  form: Partial<Test>;
  isEditMode?: boolean;
}

const props = defineProps<Props>();

defineEmits<{
  'update:form': [form: Partial<Test>];
}>();

const pipelineTypeOptions = [
  { label: 'ETL', value: 'etl' },
  { label: 'Streaming', value: 'streaming' },
  { label: 'Batch', value: 'batch' },
];

const stageOptions = [
  { label: 'Ingestion', value: 'ingestion' },
  { label: 'Transformation', value: 'transformation' },
  { label: 'Storage', value: 'storage' },
  { label: 'Export', value: 'export' },
];

const actionOptions = [
  { label: 'Read', value: 'read' },
  { label: 'Write', value: 'write' },
  { label: 'Delete', value: 'delete' },
];

const expectedAccessOptions = [
  { label: 'Allowed', value: 'true' },
  { label: 'Denied', value: 'false' },
];

// Initialize dataPipeline if not present
if (!props.form.dataPipeline) {
  props.form.dataPipeline = {
    pipelineType: '',
    stage: '',
    action: '',
    expectedAccess: undefined,
    securityControls: { encryption: false, accessControl: false, auditLogging: false }
  };
}
</script>

<style scoped>
.data-pipeline-test-form {
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

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  cursor: pointer;
}
</style>
