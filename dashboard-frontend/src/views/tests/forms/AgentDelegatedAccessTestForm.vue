<template>
  <div class="agent-test-form">
    <h3 class="section-title">Delegated Access Configuration</h3>
    
    <div class="form-section">
      <h4 class="subsection-title">Agent Configuration</h4>
      <div class="form-grid">
        <div class="form-group">
          <label>Agent ID *</label>
          <input 
            v-model="agentConfig.agentId" 
            type="text" 
            required 
            class="form-input" 
            placeholder="agent-001"
            @input="updateForm"
          />
        </div>
      </div>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">User Context</h4>
      <div class="form-grid">
        <div class="form-group">
          <label>User ID *</label>
          <input 
            v-model="agentConfig.userContext.userId" 
            type="text" 
            required 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Email *</label>
          <input 
            v-model="agentConfig.userContext.email" 
            type="email" 
            required 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Role *</label>
          <input 
            v-model="agentConfig.userContext.role" 
            type="text" 
            required 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Permissions (comma-separated)</label>
          <input 
            v-model="permissionsInput" 
            type="text" 
            class="form-input" 
            placeholder="read:emails, write:documents"
            @input="updateForm"
          />
        </div>
      </div>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">Resources</h4>
      <div v-for="(resource, index) in agentConfig.resources" :key="index" class="resource-item">
        <div class="form-grid">
          <div class="form-group">
            <label>Resource ID</label>
            <input v-model="resource.id" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Resource Type</label>
            <input v-model="resource.type" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <button type="button" @click="removeResource(index)" class="btn-danger btn-sm">Remove</button>
          </div>
        </div>
      </div>
      <button type="button" @click="addResource" class="btn-secondary">Add Resource</button>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">Actions</h4>
      <div class="form-group">
        <label>Actions (comma-separated) *</label>
        <input 
          v-model="actionsInput" 
          type="text" 
          required 
          class="form-input" 
          placeholder="read, write"
          @input="updateForm"
        />
      </div>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">OAuth Configuration (Optional)</h4>
      <div class="form-grid">
        <div class="form-group">
          <label>Authorization Endpoint</label>
          <input 
            v-model="agentConfig.oauthConfig.authorizationEndpoint" 
            type="url" 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Token Endpoint</label>
          <input 
            v-model="agentConfig.oauthConfig.tokenEndpoint" 
            type="url" 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Client ID</label>
          <input 
            v-model="agentConfig.oauthConfig.clientId" 
            type="text" 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Redirect URI</label>
          <input 
            v-model="agentConfig.oauthConfig.redirectUri" 
            type="url" 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Scopes (comma-separated)</label>
          <input 
            v-model="scopesInput" 
            type="text" 
            class="form-input" 
            placeholder="read:emails, write:documents"
            @input="updateForm"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import type { DelegatedAccessTestRequest } from '../../../composables/useAgentTests';

const props = defineProps<{
  form: any;
  isEditMode?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:form', value: any): void;
}>();

const agentConfig = ref<DelegatedAccessTestRequest>({
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

const updateForm = () => {
  // Parse comma-separated inputs
  agentConfig.value.userContext.permissions = permissionsInput.value
    .split(',')
    .map(p => p.trim())
    .filter(p => p);
  agentConfig.value.actions = actionsInput.value
    .split(',')
    .map(a => a.trim())
    .filter(a => a);
  
  if (agentConfig.value.oauthConfig && scopesInput.value) {
    agentConfig.value.oauthConfig.scopes = scopesInput.value
      .split(',')
      .map(s => s.trim())
      .filter(s => s);
  }

  // Store in form.agentConfig
  props.form.agentConfig = agentConfig.value;
  emit('update:form', props.form);
};

const addResource = () => {
  agentConfig.value.resources.push({ id: '', type: '' });
  updateForm();
};

const removeResource = (index: number) => {
  agentConfig.value.resources.splice(index, 1);
  updateForm();
};

// Load existing data if in edit mode
onMounted(() => {
  if (props.form.agentConfig) {
    agentConfig.value = { ...props.form.agentConfig };
    permissionsInput.value = agentConfig.value.userContext.permissions.join(', ');
    actionsInput.value = agentConfig.value.actions.join(', ');
    if (agentConfig.value.oauthConfig?.scopes) {
      scopesInput.value = agentConfig.value.oauthConfig.scopes.join(', ');
    }
  }
});

watch(() => props.form, () => {
  if (props.form.agentConfig) {
    agentConfig.value = { ...props.form.agentConfig };
  }
}, { deep: true });
</script>

<style scoped>
.agent-test-form {
  padding: var(--spacing-lg);
}

.section-title {
  font-size: var(--font-size-lg);
  font-weight: 600;
  margin-bottom: var(--spacing-lg);
}

.subsection-title {
  font-size: var(--font-size-base);
  font-weight: 600;
  margin-bottom: var(--spacing-md);
  margin-top: var(--spacing-lg);
}

.form-section {
  margin-bottom: var(--spacing-xl);
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
}

.form-input {
  padding: var(--spacing-sm);
  border: 1px solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
}

.resource-item {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-sm);
  margin-bottom: var(--spacing-md);
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
</style>
