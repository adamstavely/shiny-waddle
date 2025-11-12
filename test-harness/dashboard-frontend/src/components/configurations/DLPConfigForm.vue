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
  ...(props.config || props.modelValue || {}),
});

watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    Object.assign(localData.value, newVal);
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

