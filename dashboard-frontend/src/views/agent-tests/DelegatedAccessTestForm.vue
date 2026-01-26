<template>
  <div class="test-form">
    <form @submit.prevent="runTest" class="form">
      <div class="form-section">
        <h3 class="form-section-title">Agent Configuration</h3>
        <div class="form-grid">
          <div class="form-group">
            <label>Agent ID *</label>
            <input v-model="form.agentId" type="text" required class="form-input" placeholder="agent-001" />
          </div>
        </div>
      </div>

      <div class="form-section">
        <h3 class="form-section-title">User Context</h3>
        <div class="form-grid">
          <div class="form-group">
            <label>User ID *</label>
            <input v-model="form.userContext.userId" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Email *</label>
            <input v-model="form.userContext.email" type="email" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Role *</label>
            <input v-model="form.userContext.role" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Permissions (comma-separated)</label>
            <input v-model="permissionsInput" type="text" class="form-input" placeholder="read:emails, write:documents" />
          </div>
        </div>
      </div>

      <div class="form-section">
        <h3 class="form-section-title">Resources</h3>
        <div v-for="(resource, index) in form.resources" :key="index" class="resource-item">
          <div class="form-grid">
            <div class="form-group">
              <label>Resource ID</label>
              <input v-model="resource.id" type="text" class="form-input" />
            </div>
            <div class="form-group">
              <label>Resource Type</label>
              <input v-model="resource.type" type="text" class="form-input" />
            </div>
            <div class="form-group">
              <button type="button" @click="removeResource(index)" class="btn-danger btn-sm">Remove</button>
            </div>
          </div>
        </div>
        <button type="button" @click="addResource" class="btn-secondary">Add Resource</button>
      </div>

      <div class="form-section">
        <h3 class="form-section-title">Actions</h3>
        <div class="form-group">
          <label>Actions (comma-separated) *</label>
          <input v-model="actionsInput" type="text" required class="form-input" placeholder="read, write" />
        </div>
      </div>

      <div class="form-section">
        <h3 class="form-section-title">OAuth Configuration (Optional)</h3>
        <div class="form-grid">
          <div class="form-group">
            <label>Authorization Endpoint</label>
            <input v-model="form.oauthConfig.authorizationEndpoint" type="url" class="form-input" />
          </div>
          <div class="form-group">
            <label>Token Endpoint</label>
            <input v-model="form.oauthConfig.tokenEndpoint" type="url" class="form-input" />
          </div>
          <div class="form-group">
            <label>Client ID</label>
            <input v-model="form.oauthConfig.clientId" type="text" class="form-input" />
          </div>
          <div class="form-group">
            <label>Redirect URI</label>
            <input v-model="form.oauthConfig.redirectUri" type="url" class="form-input" />
          </div>
          <div class="form-group">
            <label>Scopes (comma-separated)</label>
            <input v-model="scopesInput" type="text" class="form-input" placeholder="read:emails, write:documents" />
          </div>
        </div>
      </div>

      <div class="form-actions">
        <button type="submit" :disabled="loading" class="btn-primary">
          <Play v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Running Test...' : 'Run Test' }}
        </button>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { Play } from 'lucide-vue-next';
import { useAgentTests } from '../../composables/useAgentTests';
import type { DelegatedAccessTestRequest } from '../../composables/useAgentTests';

const emit = defineEmits<{
  (e: 'test-complete', result: any): void;
}>();

const { loading, error, runDelegatedAccessTests } = useAgentTests();

const form = ref<DelegatedAccessTestRequest>({
  agentId: '',
  userContext: {
    userId: '',
    email: '',
    role: '',
    permissions: [],
  },
  resources: [{ id: '', type: '' }],
  actions: [],
  oauthConfig: {
    authorizationEndpoint: '',
    tokenEndpoint: '',
    clientId: '',
    redirectUri: '',
    scopes: [],
  },
});

const permissionsInput = ref('');
const actionsInput = ref('');
const scopesInput = ref('');

const addResource = () => {
  form.value.resources.push({ id: '', type: '' });
};

const removeResource = (index: number) => {
  form.value.resources.splice(index, 1);
};

const runTest = async () => {
  // Parse comma-separated inputs
  form.value.userContext.permissions = permissionsInput.value
    .split(',')
    .map(p => p.trim())
    .filter(p => p);
  form.value.actions = actionsInput.value
    .split(',')
    .map(a => a.trim())
    .filter(a => a);
  
  if (form.value.oauthConfig && scopesInput.value) {
    form.value.oauthConfig.scopes = scopesInput.value
      .split(',')
      .map(s => s.trim())
      .filter(s => s);
  }

  // Remove empty OAuth config if not filled
  if (!form.value.oauthConfig?.clientId) {
    delete form.value.oauthConfig;
  }

  try {
    const result = await runDelegatedAccessTests(form.value);
    emit('test-complete', result);
  } catch (err) {
    console.error('Test failed:', err);
  }
};
</script>

<style scoped>
.test-form {
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-xl);
}

.form-section {
  margin-bottom: var(--spacing-xl);
}

.form-section-title {
  font-size: var(--font-size-lg);
  font-weight: 600;
  margin-bottom: var(--spacing-md);
  color: var(--color-text-primary);
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-md);
}

.form-group {
  display: flex;
  flex-direction: column;
}

.form-group label {
  margin-bottom: var(--spacing-xs);
  font-weight: 500;
  color: var(--color-text-primary);
}

.form-input {
  padding: var(--spacing-sm);
  border: 1px solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-base);
}

.resource-item {
  padding: var(--spacing-md);
  background: var(--color-bg-primary);
  border-radius: var(--border-radius-sm);
  margin-bottom: var(--spacing-md);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-md);
  margin-top: var(--spacing-xl);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: 500;
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-secondary);
  border: 1px solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  cursor: pointer;
}

.btn-danger {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-error);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
}

.btn-sm {
  font-size: var(--font-size-sm);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.loading-spinner-small {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
