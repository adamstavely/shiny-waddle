<template>
  <div class="idp-config-form">
    <div class="form-section">
      <h3>Identity Provider Configuration</h3>
      <div class="form-group">
        <label>Type *</label>
        <select v-model="localConfig.type" required>
          <option value="ldap">LDAP</option>
          <option value="active-directory">Active Directory</option>
          <option value="okta">Okta</option>
          <option value="auth0">Auth0</option>
          <option value="azure-ad">Azure AD</option>
          <option value="google-workspace">Google Workspace</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div class="form-group">
        <label>Endpoint *</label>
        <input v-model="localConfig.endpoint" type="url" required placeholder="https://idp.example.com" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localConfig.enabled" type="checkbox" />
          Enabled
        </label>
      </div>
    </div>

    <div class="form-section">
      <h3>Authentication</h3>
      <div class="form-group">
        <label>Authentication Type *</label>
        <select v-model="localConfig.authentication.type" required>
          <option value="basic">Basic Auth</option>
          <option value="bearer">Bearer Token</option>
          <option value="api-key">API Key</option>
          <option value="oauth2">OAuth2</option>
        </select>
      </div>

      <!-- Basic Auth -->
      <template v-if="localConfig.authentication.type === 'basic'">
        <div class="form-group">
          <label>Username</label>
          <input v-model="authCredentials.username" type="text" placeholder="username" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input v-model="authCredentials.password" type="password" placeholder="password" />
        </div>
      </template>

      <!-- Bearer Token -->
      <template v-if="localConfig.authentication.type === 'bearer'">
        <div class="form-group">
          <label>Token</label>
          <input v-model="authCredentials.token" type="password" placeholder="Bearer token" />
        </div>
      </template>

      <!-- API Key -->
      <template v-if="localConfig.authentication.type === 'api-key'">
        <div class="form-group">
          <label>Header Name</label>
          <input v-model="authCredentials.headerName" type="text" placeholder="X-API-Key" />
        </div>
        <div class="form-group">
          <label>API Key</label>
          <input v-model="authCredentials.apiKey" type="password" placeholder="API key value" />
        </div>
      </template>

      <!-- OAuth2 -->
      <template v-if="localConfig.authentication.type === 'oauth2'">
        <div class="form-group">
          <label>Client ID</label>
          <input v-model="authCredentials.clientId" type="text" placeholder="OAuth2 client ID" />
        </div>
        <div class="form-group">
          <label>Client Secret</label>
          <input v-model="authCredentials.clientSecret" type="password" placeholder="OAuth2 client secret" />
        </div>
        <div class="form-group">
          <label>Token URL</label>
          <input v-model="authCredentials.tokenUrl" type="url" placeholder="https://idp.example.com/oauth/token" />
        </div>
      </template>
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
import type { IdPConfig } from '../../types/iam';

const props = defineProps<{
  config: IdPConfig;
}>();

const emit = defineEmits<{
  'update:config': [config: IdPConfig];
}>();

const localConfig = ref<IdPConfig>({ ...props.config });
const optionsJson = ref(JSON.stringify(props.config.options || {}, null, 2));
const authCredentials = ref<Record<string, string>>(props.config.authentication?.credentials || {});

watch(() => props.config, (newConfig) => {
  localConfig.value = { ...newConfig };
  optionsJson.value = JSON.stringify(newConfig.options || {}, null, 2);
  authCredentials.value = { ...(newConfig.authentication?.credentials || {}) };
}, { deep: true });

watch(localConfig, (newConfig) => {
  emit('update:config', { ...newConfig });
}, { deep: true });

watch(authCredentials, (newCreds) => {
  localConfig.value.authentication.credentials = { ...newCreds };
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
.idp-config-form {
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

