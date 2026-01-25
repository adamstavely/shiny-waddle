<template>
  <div class="api-security-test-form">
    <h3 class="section-title">API Security Configuration</h3>
    
    <div class="form-group">
      <label>API Security Test Type *</label>
      <Dropdown
        v-model="apiSecuritySubType"
        :options="apiSecuritySubTypeOptions"
        placeholder="Select API security test type..."
        class="form-input"
        @change="handleSubTypeChange"
      />
    </div>

    <!-- API Versioning -->
    <div v-if="apiSecuritySubType === 'apiVersion'" class="form-section">
      <div class="form-grid">
        <div class="form-group">
          <label>API Version *</label>
          <input v-model="form.apiVersion!.version" type="text" required placeholder="e.g., v1, v2" class="form-input" />
        </div>
        <div class="form-group">
          <label>Endpoint *</label>
          <input v-model="form.apiVersion!.endpoint" type="text" required placeholder="/api/v1/users" class="form-input" />
        </div>
      </div>
      <div class="form-group">
        <label>
          <input v-model="form.apiVersion!.deprecated" type="checkbox" />
          Deprecated
        </label>
      </div>
      <div v-if="form.apiVersion!.deprecated" class="form-grid">
        <div class="form-group">
          <label>Deprecation Date</label>
          <input v-model="form.apiVersion!.deprecationDate" type="date" class="form-input" />
        </div>
        <div class="form-group">
          <label>Sunset Date</label>
          <input v-model="form.apiVersion!.sunsetDate" type="date" class="form-input" />
        </div>
      </div>
    </div>

    <!-- GraphQL Security -->
    <div v-if="apiSecuritySubType === 'graphql'" class="form-section">
      <div class="form-group">
        <label>GraphQL Endpoint *</label>
        <input v-model="form.graphql!.endpoint" type="text" required placeholder="/graphql" class="form-input" />
      </div>
      <div class="form-group">
        <label>Schema *</label>
        <textarea v-model="form.graphql!.schema" rows="5" required class="form-input" placeholder="GraphQL schema..."></textarea>
      </div>
      <div class="form-group">
        <label>Test Type *</label>
        <Dropdown
          v-model="form.graphql!.testType"
          :options="graphqlTestTypeOptions"
          placeholder="Select GraphQL test type..."
          required
          class="form-input"
        />
      </div>
      <div v-if="form.graphql!.testType === 'depth'" class="form-group">
        <label>Max Depth</label>
        <input v-model.number="form.graphql!.maxDepth" type="number" class="form-input" />
      </div>
      <div v-if="form.graphql!.testType === 'complexity'" class="form-group">
        <label>Max Complexity</label>
        <input v-model.number="form.graphql!.maxComplexity" type="number" class="form-input" />
      </div>
      <div v-if="form.graphql!.testType === 'introspection'" class="form-group">
        <label>
          <input v-model="form.graphql!.introspectionEnabled" type="checkbox" />
          Introspection Enabled
        </label>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
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

const apiSecuritySubType = ref<'apiVersion' | 'gatewayPolicy' | 'webhook' | 'graphql' | 'apiContract'>('apiVersion');

const apiSecuritySubTypeOptions = [
  { label: 'API Versioning', value: 'apiVersion' },
  { label: 'Gateway Policy', value: 'gatewayPolicy' },
  { label: 'Webhook Security', value: 'webhook' },
  { label: 'GraphQL Security', value: 'graphql' },
  { label: 'API Contract', value: 'apiContract' },
];

const graphqlTestTypeOptions = [
  { label: 'Query Depth', value: 'depth' },
  { label: 'Query Complexity', value: 'complexity' },
  { label: 'Introspection', value: 'introspection' },
];

const handleSubTypeChange = () => {
  // Initialize form fields based on sub type
  if (apiSecuritySubType.value === 'apiVersion' && !props.form.apiVersion) {
    props.form.apiVersion = { version: '', endpoint: '', deprecated: false, deprecationDate: undefined, sunsetDate: undefined };
  } else if (apiSecuritySubType.value === 'graphql' && !props.form.graphql) {
    props.form.graphql = { endpoint: '', schema: '', testType: 'depth', maxDepth: undefined, maxComplexity: undefined, introspectionEnabled: false };
  }
};

// Initialize form when component mounts
watch(() => props.form, () => {
  if (props.form.apiVersion) {
    apiSecuritySubType.value = 'apiVersion';
  } else if (props.form.graphql) {
    apiSecuritySubType.value = 'graphql';
  }
}, { immediate: true });
</script>

<style scoped>
.api-security-test-form {
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
</style>
