<template>
  <div class="rbac-config-form">
    <div class="form-section">
      <h3>RBAC Configuration</h3>
      <div class="form-group">
        <label>Provider *</label>
        <select v-model="localConfig.provider" required>
          <option value="okta">Okta</option>
          <option value="auth0">Auth0</option>
          <option value="azure-ad">Azure AD</option>
          <option value="aws-iam">AWS IAM</option>
          <option value="gcp-iam">GCP IAM</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div class="form-group">
        <label>Endpoint *</label>
        <input v-model="localConfig.endpoint" type="url" required placeholder="https://api.example.com" />
      </div>
      <div class="form-group">
        <label>API Key</label>
        <input v-model="localConfig.apiKey" type="password" placeholder="Enter API key" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localConfig.enabled" type="checkbox" />
          Enabled
        </label>
      </div>
    </div>

    <div class="form-section">
      <h3>Additional Options</h3>
      <div class="form-group">
        <label>Options (JSON)</label>
        <textarea
          v-model="optionsJson"
          rows="4"
          placeholder='{"key": "value"}'
        ></textarea>
        <small>Optional: Additional provider-specific configuration</small>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import type { RBACConfig } from '../../types/iam';

const props = defineProps<{
  config: RBACConfig;
}>();

const emit = defineEmits<{
  'update:config': [config: RBACConfig];
}>();

const localConfig = ref<RBACConfig>({ ...props.config });
const optionsJson = ref(JSON.stringify(props.config.options || {}, null, 2));

watch(() => props.config, (newConfig) => {
  localConfig.value = { ...newConfig };
  optionsJson.value = JSON.stringify(newConfig.options || {}, null, 2);
}, { deep: true });

watch(localConfig, (newConfig) => {
  emit('update:config', { ...newConfig });
}, { deep: true });

watch(optionsJson, (newValue) => {
  try {
    localConfig.value.options = JSON.parse(newValue);
  } catch {
    // Invalid JSON, ignore
  }
});
</script>

<style scoped>
.rbac-config-form {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.form-section {
  background: rgba(15, 20, 25, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 20px;
}

.form-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.form-group {
  margin-bottom: 16px;
}

.form-group:last-child {
  margin-bottom: 0;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-group input[type="text"],
.form-group input[type="url"],
.form-group input[type="password"],
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 10px 12px;
  background: rgba(15, 20, 25, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.9rem;
  font-family: inherit;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
}

.form-group input[type="checkbox"] {
  width: auto;
  margin-right: 8px;
}

.form-group small {
  display: block;
  margin-top: 4px;
  font-size: 0.75rem;
  color: #718096;
}
</style>

