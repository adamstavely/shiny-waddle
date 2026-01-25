<template>
  <div class="dlp-config-form">
    <div class="form-section">
      <h3>DLP Patterns</h3>
      <div v-for="(pattern, index) in localData.patterns" :key="index" class="pattern-item">
        <div class="form-group">
          <label>Pattern Name *</label>
          <input v-model="pattern.name" type="text" required />
        </div>
        <div class="form-group">
          <label>Pattern (Regex)</label>
          <input v-model="pattern.pattern" type="text" />
        </div>
        <div class="form-group">
          <label>Pattern Type</label>
          <select v-model="pattern.type">
            <option value="ssn">SSN</option>
            <option value="credit-card">Credit Card</option>
            <option value="email">Email</option>
            <option value="phone">Phone</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <button @click="removePattern(index)" class="btn-danger">Remove</button>
      </div>
      <button @click="addPattern" class="btn-secondary">Add Pattern</button>
    </div>

    <div class="form-section">
      <h3>Bulk Export Limits</h3>
      <div class="form-group">
        <label>Maximum Records (CSV)</label>
        <input v-model.number="localData.bulkExportLimits.csv" type="number" />
      </div>
      <div class="form-group">
        <label>Maximum Records (JSON)</label>
        <input v-model.number="localData.bulkExportLimits.json" type="number" />
      </div>
      <div class="form-group">
        <label>Maximum Records (Excel)</label>
        <input v-model.number="localData.bulkExportLimits.excel" type="number" />
      </div>
      <div class="form-group">
        <label>Maximum Records (API)</label>
        <input v-model.number="localData.bulkExportLimits.api" type="number" />
      </div>
    </div>

    <div class="form-section">
      <h3>PII Detection Rules</h3>
      <div class="form-group">
        <label>PII Fields (comma-separated)</label>
        <input v-model="localData.piiFields" type="text" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.requireEncryption" type="checkbox" />
          Require Encryption for PII
        </label>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.blockExfiltration" type="checkbox" />
          Block Data Exfiltration
        </label>
      </div>
    </div>

    <div class="form-section">
      <h3>Export Restrictions</h3>
      <div class="form-group">
        <label>Restricted Fields (comma-separated)</label>
        <input 
          v-model="restrictedFieldsInput" 
          type="text" 
          placeholder="email, ssn, phone"
          @blur="updateRestrictedFields"
        />
        <small class="form-help">Fields that cannot be exported</small>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.exportRestrictions.requireMasking" type="checkbox" />
          Require Masking for Restricted Fields
        </label>
      </div>
      <div class="form-group">
        <label>Allowed Export Formats (comma-separated)</label>
        <input 
          v-model="allowedFormatsInput" 
          type="text" 
          placeholder="csv, json"
          @blur="updateAllowedFormats"
        />
        <small class="form-help">Leave empty to allow all formats</small>
      </div>
    </div>

    <div class="form-section">
      <h3>Aggregation Requirements</h3>
      <div class="form-group">
        <label>
          <input v-model="localData.aggregationRequirements.requireAggregation" type="checkbox" />
          Require Aggregation
        </label>
      </div>
      <div class="form-group">
        <label>Minimum k (Records per Group)</label>
        <input 
          v-model.number="localData.aggregationRequirements.minK" 
          type="number" 
          min="1"
          placeholder="10"
        />
        <small class="form-help">Minimum number of records required per aggregation group</small>
      </div>
    </div>

    <div class="form-section">
      <h3>Field Restrictions</h3>
      <div class="form-group">
        <label>Disallowed Fields (comma-separated)</label>
        <input 
          v-model="disallowedFieldsInput" 
          type="text" 
          placeholder="ssn, credit_card"
          @blur="updateDisallowedFields"
        />
        <small class="form-help">Fields that cannot be accessed in queries</small>
      </div>
      <div class="form-group">
        <label>Allowed Fields (comma-separated)</label>
        <input 
          v-model="allowedFieldsInput" 
          type="text" 
          placeholder="id, name, status"
          @blur="updateAllowedFields"
        />
        <small class="form-help">Whitelist of allowed fields (leave empty to allow all except disallowed)</small>
      </div>
    </div>

    <div class="form-section">
      <h3>Join Restrictions</h3>
      <div class="form-group">
        <label>Disallowed Joins (comma-separated table names)</label>
        <input 
          v-model="disallowedJoinsInput" 
          type="text" 
          placeholder="users, user_profiles"
          @blur="updateDisallowedJoins"
        />
        <small class="form-help">Tables that cannot be joined in queries</small>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';

const props = defineProps<{
  config?: any;
  modelValue?: any;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: any];
}>();

const localData = ref({
  patterns: [] as any[],
  bulkExportLimits: {
    csv: 10000,
    json: 10000,
    excel: 10000,
    api: 1000,
  },
  piiFields: '',
  testLogic: {
    requireEncryption: true,
    blockExfiltration: true,
  },
  exportRestrictions: {
    restrictedFields: [] as string[],
    requireMasking: false,
    allowedFormats: [] as string[],
  },
  aggregationRequirements: {
    minK: undefined as number | undefined,
    requireAggregation: false,
  },
  fieldRestrictions: {
    disallowedFields: [] as string[],
    allowedFields: [] as string[],
  },
  joinRestrictions: {
    disallowedJoins: [] as string[],
  },
  ...(props.config || props.modelValue || {}),
});

// Input fields for comma-separated values
const restrictedFieldsInput = ref(
  (localData.value.exportRestrictions?.restrictedFields || []).join(', ')
);
const allowedFormatsInput = ref(
  (localData.value.exportRestrictions?.allowedFormats || []).join(', ')
);
const disallowedFieldsInput = ref(
  (localData.value.fieldRestrictions?.disallowedFields || []).join(', ')
);
const allowedFieldsInput = ref(
  (localData.value.fieldRestrictions?.allowedFields || []).join(', ')
);
const disallowedJoinsInput = ref(
  (localData.value.joinRestrictions?.disallowedJoins || []).join(', ')
);

const updateRestrictedFields = () => {
  localData.value.exportRestrictions.restrictedFields = restrictedFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateAllowedFormats = () => {
  localData.value.exportRestrictions.allowedFormats = allowedFormatsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateDisallowedFields = () => {
  localData.value.fieldRestrictions.disallowedFields = disallowedFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateAllowedFields = () => {
  localData.value.fieldRestrictions.allowedFields = allowedFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateDisallowedJoins = () => {
  localData.value.joinRestrictions.disallowedJoins = disallowedJoinsInput.value
    .split(',')
    .map(j => j.trim())
    .filter(j => j.length > 0);
};

watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    Object.assign(localData.value, newVal);
    // Update input fields
    restrictedFieldsInput.value = (newVal.exportRestrictions?.restrictedFields || []).join(', ');
    allowedFormatsInput.value = (newVal.exportRestrictions?.allowedFormats || []).join(', ');
    disallowedFieldsInput.value = (newVal.fieldRestrictions?.disallowedFields || []).join(', ');
    allowedFieldsInput.value = (newVal.fieldRestrictions?.allowedFields || []).join(', ');
    disallowedJoinsInput.value = (newVal.joinRestrictions?.disallowedJoins || []).join(', ');
  }
}, { deep: true });

watch(localData, (newVal) => {
  emit('update:modelValue', { ...props.modelValue, ...newVal });
}, { deep: true });

const addPattern = () => {
  localData.value.patterns.push({
    name: '',
    pattern: '',
    type: 'custom',
  });
};

const removePattern = (index: number) => {
  localData.value.patterns.splice(index, 1);
};
</script>

<style scoped>
.dlp-config-form {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.form-section {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1.5rem;
  background: rgba(15, 20, 25, 0.4);
}

.form-section h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: #a0aec0;
  font-size: 0.9rem;
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #ffffff;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group select option {
  background: #1a1f2e;
  color: #ffffff;
}

.form-help {
  display: block;
  margin-top: 0.25rem;
  font-size: 0.75rem;
  color: #718096;
  font-style: italic;
}

.pattern-item {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
  background: rgba(15, 20, 25, 0.2);
}

.btn-secondary,
.btn-danger {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-danger {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.btn-danger:hover {
  background: rgba(252, 129, 129, 0.2);
  border-color: rgba(252, 129, 129, 0.5);
}
</style>

