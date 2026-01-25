<template>
  <div class="sso-config-form">
    <div class="form-section">
      <h3>SSO Configuration</h3>
      <div class="form-group">
        <label>Type *</label>
        <select v-model="localConfig.type" required>
          <option value="saml">SAML</option>
          <option value="oidc">OIDC</option>
        </select>
      </div>
      <div class="form-group">
        <label>Endpoint *</label>
        <input v-model="localConfig.endpoint" type="url" required placeholder="https://sso.example.com" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localConfig.enabled" type="checkbox" />
          Enabled
        </label>
      </div>
    </div>

    <!-- SAML-specific fields -->
    <div v-if="localConfig.type === 'saml'" class="form-section">
      <h3>SAML Configuration</h3>
      <div class="form-group">
        <label>Entity ID</label>
        <input v-model="localConfig.entityId" type="text" placeholder="urn:example:sp" />
      </div>
      <div class="form-group">
        <label>Certificate</label>
        <textarea v-model="localConfig.certificate" rows="5" placeholder="Paste certificate here"></textarea>
      </div>
      <div class="form-group">
        <label>Private Key</label>
        <textarea v-model="localConfig.privateKey" rows="5" placeholder="Paste private key here"></textarea>
      </div>
    </div>

    <!-- OIDC-specific fields -->
    <div v-if="localConfig.type === 'oidc'" class="form-section">
      <h3>OIDC Configuration</h3>
      <div class="form-group">
        <label>Client ID *</label>
        <input v-model="localConfig.clientId" type="text" required placeholder="your-client-id" />
      </div>
      <div class="form-group">
        <label>Client Secret *</label>
        <input v-model="localConfig.clientSecret" type="password" required placeholder="your-client-secret" />
      </div>
      <div class="form-group">
        <label>Redirect URI *</label>
        <input v-model="localConfig.redirectUri" type="url" required placeholder="https://app.example.com/callback" />
      </div>
      <div class="form-group">
        <label>Scopes (comma-separated)</label>
        <input v-model="scopesInput" type="text" placeholder="openid, profile, email" />
        <small>Default: openid, profile, email</small>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import type { SSOConfig } from '../../types/iam';

const props = defineProps<{
  config: SSOConfig;
}>();

const emit = defineEmits<{
  'update:config': [config: SSOConfig];
}>();

const localConfig = ref<SSOConfig>({ ...props.config });
const scopesInput = ref(props.config.scopes?.join(', ') || 'openid, profile, email');

watch(() => props.config, (newConfig) => {
  localConfig.value = { ...newConfig };
  scopesInput.value = newConfig.scopes?.join(', ') || 'openid, profile, email';
}, { deep: true });

watch(localConfig, (newConfig) => {
  emit('update:config', { ...newConfig });
}, { deep: true });

watch(scopesInput, (newValue) => {
  localConfig.value.scopes = newValue.split(',').map(s => s.trim()).filter(Boolean);
});
</script>

<style scoped>
.sso-config-form {
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

