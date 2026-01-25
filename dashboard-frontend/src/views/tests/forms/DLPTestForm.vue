<template>
  <div class="dlp-test-form">
    <h3 class="section-title">DLP Configuration</h3>
    
    <div class="form-group">
      <label>DLP Test Type *</label>
      <Dropdown
        v-model="dlpTestType"
        :options="dlpTestTypeOptions"
        placeholder="Select DLP test type..."
        class="form-input"
        @change="handleTestTypeChange"
      />
    </div>

    <!-- Pattern Test -->
    <div v-if="dlpTestType === 'pattern'" class="form-section">
      <div class="form-group">
        <label>Pattern Name</label>
        <input v-model="form.pattern!.name" type="text" class="form-input" />
      </div>
      <div class="form-group">
        <label>Pattern Type</label>
        <Dropdown
          v-model="form.pattern!.type"
          :options="patternTypeOptions"
          placeholder="Select pattern type..."
          class="form-input"
        />
      </div>
      <div class="form-group">
        <label>Pattern (Regex) *</label>
        <input v-model="form.pattern!.pattern" type="text" required class="form-input" />
      </div>
      <div class="form-group">
        <label>Expected Detection *</label>
        <Dropdown
          v-model="form.expectedDetection"
          :options="expectedDetectionOptions"
          placeholder="Select expected detection..."
          required
          class="form-input"
        />
      </div>
    </div>

    <!-- Bulk Export Test -->
    <div v-if="dlpTestType === 'bulk-export'" class="form-section">
      <div class="form-grid">
        <div class="form-group">
          <label>Export Type *</label>
          <Dropdown
            v-model="form.bulkExportType"
            :options="exportTypeOptions"
            placeholder="Select export type..."
            required
            class="form-input"
          />
        </div>
        <div class="form-group">
          <label>Limit</label>
          <input v-model.number="form.bulkExportLimit" type="number" class="form-input" />
        </div>
        <div class="form-group">
          <label>Test Record Count</label>
          <input v-model.number="form.testRecordCount" type="number" class="form-input" />
        </div>
      </div>
      <div class="form-group">
        <label>Expected Blocked *</label>
        <Dropdown
          v-model="form.expectedBlocked"
          :options="expectedBlockedOptions"
          placeholder="Select expected result..."
          required
          class="form-input"
        />
      </div>
    </div>

    <!-- Export Restrictions Test -->
    <div v-if="dlpTestType === 'export-restrictions'" class="form-section">
      <div class="form-group">
        <label>Restricted Fields (comma-separated) *</label>
        <input 
          v-model="restrictedFieldsInput" 
          type="text" 
          placeholder="email, ssn, phone"
          class="form-input"
          @blur="updateRestrictedFields"
        />
        <p class="field-help">Fields that cannot be exported</p>
      </div>
      <div class="form-group">
        <label>
          <input v-model="form.exportRestrictions!.requireMasking" type="checkbox" />
          Require Masking
        </label>
      </div>
      <div class="form-group">
        <label>Allowed Formats (comma-separated)</label>
        <input 
          v-model="allowedFormatsInput" 
          type="text" 
          placeholder="csv, json"
          class="form-input"
          @blur="updateAllowedFormats"
        />
      </div>
    </div>

    <!-- RLS/CLS Test -->
    <div v-if="dlpTestType === 'rls-cls'" class="form-section">
      <div class="form-group">
        <label>Database Type *</label>
        <Dropdown
          v-model="form.rlsCls!.database.type"
          :options="databaseTypeOptions"
          placeholder="Select database type..."
          required
          class="form-input"
        />
      </div>
      <div class="form-group">
        <label>Connection String</label>
        <input v-model="form.rlsCls!.database.connectionString" type="text" class="form-input" />
      </div>
      <div class="form-group">
        <label>Test Queries *</label>
        <p class="field-help">At least one test query is required</p>
        <div v-for="(query, index) in form.rlsCls!.testQueries" :key="index" class="query-item">
          <div class="form-grid">
            <div class="form-group">
              <label>Query Name</label>
              <input v-model="query.name" type="text" class="form-input" />
            </div>
            <div class="form-group">
              <label>SQL Query</label>
              <textarea v-model="query.sql" rows="3" class="form-input"></textarea>
            </div>
          </div>
          <BaseButton label="Remove" variant="danger" size="sm" @click="removeQuery(index)" />
        </div>
        <BaseButton label="Add Query" variant="secondary" @click="addQuery" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import Dropdown from '../../../components/Dropdown.vue';
import BaseButton from '../../../components/BaseButton.vue';
import type { Test, PatternConfig, ExportRestrictions, RLSCLSConfig, TestQuery } from '../../../types/test';

interface Props {
  form: Partial<Test>;
  isEditMode?: boolean;
}

const props = defineProps<Props>();

defineEmits<{
  'update:form': [form: Partial<Test>];
}>();

const dlpTestType = ref<'pattern' | 'bulk-export' | 'export-restrictions' | 'rls-cls'>('pattern');
const restrictedFieldsInput = ref('');
const allowedFormatsInput = ref('');

const dlpTestTypeOptions = [
  { label: 'Pattern Detection', value: 'pattern' },
  { label: 'Bulk Export Limit', value: 'bulk-export' },
  { label: 'Export Restrictions', value: 'export-restrictions' },
  { label: 'RLS/CLS', value: 'rls-cls' },
];

const patternTypeOptions = [
  { label: 'SSN', value: 'ssn' },
  { label: 'Credit Card', value: 'credit-card' },
  { label: 'Email', value: 'email' },
  { label: 'Custom Regex', value: 'custom' },
];

const expectedDetectionOptions = [
  { label: 'Detected', value: 'true' },
  { label: 'Not Detected', value: 'false' },
];

const exportTypeOptions = [
  { label: 'CSV', value: 'csv' },
  { label: 'JSON', value: 'json' },
  { label: 'Excel', value: 'excel' },
];

const expectedBlockedOptions = [
  { label: 'Blocked', value: 'true' },
  { label: 'Allowed', value: 'false' },
];

const databaseTypeOptions = [
  { label: 'PostgreSQL', value: 'postgresql' },
  { label: 'MySQL', value: 'mysql' },
  { label: 'SQL Server', value: 'sqlserver' },
  { label: 'Snowflake', value: 'snowflake' },
];

const handleTestTypeChange = () => {
  // Initialize form fields based on test type
  if (dlpTestType.value === 'pattern' && !props.form.pattern) {
    props.form.pattern = { name: '', type: '', pattern: '' };
  } else if (dlpTestType.value === 'bulk-export') {
    props.form.bulkExportType = '';
    props.form.bulkExportLimit = 0;
    props.form.testRecordCount = 0;
    props.form.expectedBlocked = undefined;
  } else if (dlpTestType.value === 'export-restrictions' && !props.form.exportRestrictions) {
    props.form.exportRestrictions = { restrictedFields: [], requireMasking: false, allowedFormats: [] };
  } else if (dlpTestType.value === 'rls-cls' && !props.form.rlsCls) {
    props.form.rlsCls = {
      database: { type: '', host: '', port: undefined, database: '', username: '', password: '', connectionString: '' },
      testQueries: [],
      maskingRules: [],
      validationRules: { minRLSCoverage: 0, minCLSCoverage: 0, requiredPolicies: [] }
    };
  }
};

const updateRestrictedFields = () => {
  if (!props.form.exportRestrictions) {
    props.form.exportRestrictions = { restrictedFields: [], requireMasking: false, allowedFormats: [] };
  }
  props.form.exportRestrictions.restrictedFields = restrictedFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateAllowedFormats = () => {
  if (!props.form.exportRestrictions) {
    props.form.exportRestrictions = { restrictedFields: [], requireMasking: false, allowedFormats: [] };
  }
  props.form.exportRestrictions.allowedFormats = allowedFormatsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const addQuery = () => {
  if (!props.form.rlsCls) {
    props.form.rlsCls = {
      database: { type: '', host: '', port: undefined, database: '', username: '', password: '', connectionString: '' },
      testQueries: [],
      maskingRules: [],
      validationRules: { minRLSCoverage: 0, minCLSCoverage: 0, requiredPolicies: [] }
    };
  }
  props.form.rlsCls.testQueries.push({ name: '', sql: '' });
};

const removeQuery = (index: number) => {
  if (props.form.rlsCls?.testQueries) {
    props.form.rlsCls.testQueries.splice(index, 1);
  }
};

// Initialize form when component mounts
watch(() => props.form, () => {
  if (props.form.pattern) {
    dlpTestType.value = 'pattern';
  } else if (props.form.bulkExportType) {
    dlpTestType.value = 'bulk-export';
  } else if (props.form.exportRestrictions) {
    dlpTestType.value = 'export-restrictions';
    restrictedFieldsInput.value = props.form.exportRestrictions.restrictedFields?.join(', ') || '';
    allowedFormatsInput.value = props.form.exportRestrictions.allowedFormats?.join(', ') || '';
  } else if (props.form.rlsCls) {
    dlpTestType.value = 'rls-cls';
  }
}, { immediate: true });
</script>

<style scoped>
.dlp-test-form {
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
}

.query-item {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-sm);
}
</style>
