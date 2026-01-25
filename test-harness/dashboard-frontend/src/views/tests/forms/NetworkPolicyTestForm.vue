<template>
  <div class="network-policy-test-form">
    <h3 class="section-title">Network Policy Configuration</h3>
    
    <div class="form-grid">
      <div class="form-group">
        <label>Source *</label>
        <input v-model="form.networkPolicy!.source" type="text" required placeholder="e.g., 10.0.0.0/24" class="form-input" />
        <p class="field-help">Source IP address or CIDR block</p>
      </div>
      <div class="form-group">
        <label>Target *</label>
        <input v-model="form.networkPolicy!.target" type="text" required placeholder="e.g., 10.0.1.0/24" class="form-input" />
        <p class="field-help">Target IP address or CIDR block</p>
      </div>
    </div>

    <div class="form-grid">
      <div class="form-group">
        <label>Protocol *</label>
        <Dropdown
          v-model="form.networkPolicy!.protocol"
          :options="protocolOptions"
          placeholder="Select protocol..."
          required
          class="form-input"
        />
      </div>
      <div class="form-group">
        <label>Port</label>
        <input v-model.number="form.networkPolicy!.port" type="number" placeholder="e.g., 80, 443" class="form-input" />
        <p class="field-help">Optional port number</p>
      </div>
      <div class="form-group">
        <label>Expected Action *</label>
        <Dropdown
          v-model="form.networkPolicy!.action"
          :options="actionOptions"
          placeholder="Select expected action..."
          required
          class="form-input"
        />
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

const protocolOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
  { label: 'ICMP', value: 'icmp' },
  { label: 'Any', value: 'any' },
];

const actionOptions = [
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' },
];

// Initialize networkPolicy if not present
if (!props.form.networkPolicy) {
  props.form.networkPolicy = { source: '', target: '', protocol: '', port: undefined, action: '' };
}
</script>

<style scoped>
.network-policy-test-form {
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
</style>
