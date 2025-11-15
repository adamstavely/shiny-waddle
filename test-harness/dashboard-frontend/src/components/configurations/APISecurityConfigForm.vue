<template>
  <div class="api-security-config-form">
    <div class="form-section">
      <h3>API Configuration</h3>
      <div class="form-group">
        <label>Base URL *</label>
        <input v-model="localData.baseUrl" type="url" required placeholder="https://api.example.com" />
      </div>
      <div class="form-group">
        <label>Timeout (ms)</label>
        <input v-model.number="localData.timeout" type="number" placeholder="5000" />
      </div>
    </div>

    <div class="form-section">
      <h3>Authentication</h3>
      <div class="form-group">
        <label>Type</label>
        <select v-model="localData.authentication.type">
          <option value="">None</option>
          <option value="bearer">Bearer Token</option>
          <option value="basic">Basic Auth</option>
          <option value="oauth2">OAuth2</option>
          <option value="api-key">API Key</option>
          <option value="jwt">JWT</option>
        </select>
      </div>
      <div v-if="localData.authentication.type" class="form-group">
        <label>Credentials (JSON)</label>
        <textarea
          v-model="authCredentialsJson"
          rows="3"
          placeholder='{"token": "..."}'
        ></textarea>
      </div>
    </div>

    <div class="form-section">
      <h3>Rate Limiting</h3>
      <div class="form-group">
        <label>Max Requests</label>
        <input v-model.number="localData.rateLimitConfig.maxRequests" type="number" />
      </div>
      <div class="form-group">
        <label>Window (seconds)</label>
        <input v-model.number="localData.rateLimitConfig.windowSeconds" type="number" />
      </div>
      <div class="form-group">
        <label>Strategy</label>
        <select v-model="localData.rateLimitConfig.strategy">
          <option value="fixed">Fixed</option>
          <option value="sliding">Sliding</option>
          <option value="token-bucket">Token Bucket</option>
        </select>
      </div>
    </div>

    <div class="form-section">
      <h3>Test Suites</h3>
      <p class="section-description">
        Select which test suites to run. If none are selected, default behavior will be used based on endpoint API type.
      </p>
      <div class="suite-controls">
        <button @click="selectAllSuites" type="button" class="btn-suite-control">Select All</button>
        <button @click="deselectAllSuites" type="button" class="btn-suite-control">Deselect All</button>
      </div>
      <div class="test-suites-grid">
        <label v-for="suite in availableTestSuites" :key="suite.value" class="suite-checkbox-label">
          <input
            type="checkbox"
            :value="suite.value"
            v-model="localData.testLogic.selectedTestSuites"
            class="suite-checkbox"
          />
          <span class="suite-name">{{ suite.label }}</span>
        </label>
      </div>
    </div>

    <div class="form-section">
      <h3>Endpoints</h3>
      <div v-for="(endpoint, index) in localData.endpoints" :key="index" class="endpoint-item">
        <div class="form-group">
          <label>Endpoint Name *</label>
          <input v-model="endpoint.name" type="text" required />
        </div>
        <div class="form-group">
          <label>Endpoint Path *</label>
          <input v-model="endpoint.endpoint" type="text" required placeholder="/api/v1/users" />
        </div>
        <div class="form-group">
          <label>HTTP Method *</label>
          <select v-model="endpoint.method" required>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
            <option value="OPTIONS">OPTIONS</option>
          </select>
        </div>
        <div class="form-group">
          <label>API Type *</label>
          <select v-model="endpoint.apiType" required>
            <option value="rest">REST</option>
            <option value="graphql">GraphQL</option>
            <option value="authentication">Authentication</option>
            <option value="authorization">Authorization</option>
            <option value="rate-limiting">Rate Limiting</option>
            <option value="vulnerability">Vulnerability</option>
          </select>
        </div>
        <div class="form-group">
          <label>Expected Status Code</label>
          <input v-model.number="endpoint.expectedStatus" type="number" />
        </div>
        <div class="form-group">
          <label>
            <input v-model="endpoint.expectedAuthRequired" type="checkbox" />
            Authentication Required
          </label>
        </div>
        <button @click="removeEndpoint(index)" class="btn-remove">Remove</button>
      </div>
      <button @click="addEndpoint" class="btn-add">Add Endpoint</button>
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

const availableTestSuites = [
  { value: 'authentication', label: 'Authentication' },
  { value: 'authorization', label: 'Authorization' },
  { value: 'injection', label: 'Injection' },
  { value: 'rate-limiting', label: 'Rate Limiting' },
  { value: 'security-headers', label: 'Security Headers' },
  { value: 'graphql', label: 'GraphQL' },
  { value: 'sensitive-data', label: 'Sensitive Data' },
  { value: 'cryptography', label: 'Cryptography' },
  { value: 'api-design', label: 'API Design' },
  { value: 'business-logic', label: 'Business Logic' },
  { value: 'third-party', label: 'Third-Party Integration' },
  { value: 'logging', label: 'Logging' },
];

const localData = ref({
  baseUrl: '',
  timeout: 5000,
  authentication: {
    type: '',
    credentials: {} as Record<string, string>,
  },
  rateLimitConfig: {
    maxRequests: 100,
    windowSeconds: 60,
    strategy: 'fixed' as 'fixed' | 'sliding' | 'token-bucket',
  },
  headers: {},
  testLogic: {
    selectedTestSuites: [] as string[],
  },
  endpoints: [] as Array<{
    name: string;
    endpoint: string;
    method: string;
    apiType: string;
    expectedStatus?: number;
    expectedAuthRequired?: boolean;
    expectedRateLimit?: boolean;
    body?: any;
    headers?: Record<string, string>;
  }>,
});

const authCredentialsJson = ref('{}');

watch(() => props.config || props.modelValue, (newConfig) => {
  if (newConfig) {
    localData.value = {
      baseUrl: newConfig.baseUrl || '',
      timeout: newConfig.timeout || 5000,
      authentication: newConfig.authentication || { type: '', credentials: {} },
      rateLimitConfig: newConfig.rateLimitConfig || {
        maxRequests: 100,
        windowSeconds: 60,
        strategy: 'fixed',
      },
      headers: newConfig.headers || {},
      testLogic: {
        selectedTestSuites: newConfig.testLogic?.selectedTestSuites || [],
      },
      endpoints: newConfig.endpoints || [],
    };
    authCredentialsJson.value = JSON.stringify(newConfig.authentication?.credentials || {}, null, 2);
  }
}, { immediate: true });

watch([localData, authCredentialsJson], () => {
  try {
    const credentials = JSON.parse(authCredentialsJson.value || '{}');
    const dataToEmit = {
      ...localData.value,
      authentication: localData.value.authentication.type
        ? { type: localData.value.authentication.type, credentials }
        : undefined,
      rateLimitConfig: localData.value.rateLimitConfig.maxRequests
        ? localData.value.rateLimitConfig
        : undefined,
      testLogic: localData.value.testLogic.selectedTestSuites.length > 0
        ? { selectedTestSuites: localData.value.testLogic.selectedTestSuites }
        : undefined,
    };
    emit('update:modelValue', dataToEmit);
  } catch (error) {
    // Invalid JSON, emit without credentials
    const dataToEmit = {
      ...localData.value,
      testLogic: localData.value.testLogic.selectedTestSuites.length > 0
        ? { selectedTestSuites: localData.value.testLogic.selectedTestSuites }
        : undefined,
    };
    emit('update:modelValue', dataToEmit);
  }
}, { deep: true });

const addEndpoint = () => {
  localData.value.endpoints.push({
    name: '',
    endpoint: '',
    method: 'GET',
    apiType: 'rest',
    expectedAuthRequired: false,
    expectedRateLimit: false,
  });
};

const removeEndpoint = (index: number) => {
  localData.value.endpoints.splice(index, 1);
};

const selectAllSuites = () => {
  localData.value.testLogic.selectedTestSuites = availableTestSuites.map(s => s.value);
};

const deselectAllSuites = () => {
  localData.value.testLogic.selectedTestSuites = [];
};
</script>

<style scoped>
.api-security-config-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-section {
  padding: 1rem;
  background: rgba(255, 255, 255, 0.02);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.form-section h3 {
  margin: 0 0 1rem 0;
  color: #ffffff;
  font-size: 1.1rem;
  font-weight: 600;
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
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 1rem;
  color: #ffffff;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group textarea {
  resize: vertical;
  font-family: 'Courier New', monospace;
}

.form-group label input[type="checkbox"] {
  width: auto;
  margin-right: 0.5rem;
}

.section-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin-bottom: 1rem;
  line-height: 1.5;
}

.suite-controls {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.btn-suite-control {
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-suite-control:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.test-suites-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.75rem;
}

.suite-checkbox-label {
  display: flex;
  align-items: center;
  padding: 0.5rem;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid rgba(79, 172, 254, 0.1);
  cursor: pointer;
  transition: all 0.2s;
}

.suite-checkbox-label:hover {
  background: rgba(79, 172, 254, 0.05);
  border-color: rgba(79, 172, 254, 0.3);
}

.suite-checkbox {
  width: auto;
  margin-right: 0.5rem;
  cursor: pointer;
}

.suite-name {
  color: #ffffff;
  font-size: 0.9rem;
  user-select: none;
}

.endpoint-item {
  padding: 1rem;
  background: rgba(255, 255, 255, 0.02);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  margin-bottom: 1rem;
}

.btn-add,
.btn-remove {
  padding: 0.5rem 1rem;
  border-radius: 6px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-add {
  background: rgba(79, 172, 254, 0.2);
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-add:hover {
  background: rgba(79, 172, 254, 0.3);
}

.btn-remove {
  background: rgba(252, 129, 129, 0.2);
  border: 1px solid rgba(252, 129, 129, 0.3);
  color: #fc8181;
  margin-top: 0.5rem;
}

.btn-remove:hover {
  background: rgba(252, 129, 129, 0.3);
}
</style>

