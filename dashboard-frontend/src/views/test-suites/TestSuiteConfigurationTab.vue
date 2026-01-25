<template>
  <div class="test-suite-configuration-tab">
    <div class="form-section">
      <div class="section-header">
        <h2 class="section-title">Basic Configuration</h2>
      </div>
      <div class="form-grid">
        <div class="form-group">
          <label>Test Suite Name *</label>
          <input v-model="form.name" type="text" required class="form-input" />
        </div>
        <div class="form-group">
          <label>Application *</label>
          <input v-model="form.application" type="text" required class="form-input" />
        </div>
        <div class="form-group">
          <label>Team *</label>
          <input v-model="form.team" type="text" required class="form-input" />
        </div>
      </div>

      <div class="section-header">
        <h2 class="section-title">Test Type</h2>
      </div>
      <div class="form-group">
        <label>Test Type *</label>
        <select v-model="form.testType" required class="form-input form-select" @change="$emit('test-type-change', form.testType)">
          <option value="">Select a test type...</option>
          <option value="access-control">Access Control</option>
          <option value="network-policy">Network Policy</option>
          <option value="dlp">Data Loss Prevention (DLP)</option>
          <option value="distributed-systems">Distributed Systems</option>
          <option value="api-security">API Security</option>
          <option value="data-pipeline">Data Pipeline</option>
        </select>
        <small class="text-muted text-xs mt-xs" style="display: block;">
          Each test suite must have exactly one test type. All tests in this suite will be of the selected type.
        </small>
        <div v-if="form.testType" class="test-type-info">
          <p><strong>Selected:</strong> {{ getTestTypeLabel(form.testType) }}</p>
          <p class="test-generation-note">
            <Info class="info-icon-small" />
            All tests assigned to this suite must be of type: <strong>{{ getTestTypeLabel(form.testType) }}</strong>
          </p>
        </div>
      </div>
      <div class="form-group">
        <label>Description</label>
        <textarea v-model="form.description" rows="3" class="form-input"></textarea>
      </div>
      <div class="form-group">
        <label>
          <input v-model="form.enabled" type="checkbox" />
          Enabled
        </label>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { Info } from 'lucide-vue-next';

interface Props {
  form: {
    name: string;
    application: string;
    team: string;
    testType: string;
    description: string;
    enabled: boolean;
  };
}

const props = defineProps<Props>();

defineEmits<{
  'test-type-change': [testType: string];
  'update:form': [form: Props['form']];
}>();

const getTestTypeLabel = (testType: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
  };
  return labels[testType] || testType;
};
</script>

<style scoped>
.test-suite-configuration-tab {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.form-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.section-header {
  margin-bottom: var(--spacing-md);
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
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

.form-select {
  cursor: pointer;
}

.form-group small {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.test-type-info {
  margin-top: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
}

.test-generation-note {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  margin-top: var(--spacing-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.info-icon-small {
  width: 16px;
  height: 16px;
  color: var(--color-primary);
}
</style>
