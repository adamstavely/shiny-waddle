<template>
  <div class="agent-test-form">
    <h3 class="section-title">Direct Access Configuration</h3>
    
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
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Agent Type *</label>
          <select v-model="agentConfig.agentType" required class="form-input" @change="updateForm">
            <option value="autonomous">Autonomous</option>
            <option value="event-driven">Event-Driven</option>
            <option value="scheduled">Scheduled</option>
          </select>
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
          @input="updateForm"
        />
      </div>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">OAuth Configuration (Optional)</h4>
      <div class="form-grid">
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
          <label>Client Secret</label>
          <input 
            v-model="agentConfig.oauthConfig.clientSecret" 
            type="password" 
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
            @input="updateForm"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import type { DirectAccessTestRequest } from '../../../composables/useAgentTests';

const props = defineProps<{
  form: any;
  isEditMode?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:form', value: any): void;
}>();

const agentConfig = ref<DirectAccessTestRequest>({
  agentId: '',
  agentType: 'autonomous',
  resources: [{ id: '', type: '' }],
  actions: [],
  oauthConfig: {
    tokenEndpoint: '',
    clientId: '',
    scopes: [],
  },
});

const actionsInput = ref('');
const scopesInput = ref('');

const updateForm = () => {
  agentConfig.value.actions = actionsInput.value.split(',').map(a => a.trim()).filter(a => a);
  if (agentConfig.value.oauthConfig && scopesInput.value) {
    agentConfig.value.oauthConfig.scopes = scopesInput.value.split(',').map(s => s.trim()).filter(s => s);
  }
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

onMounted(() => {
  if (props.form.agentConfig) {
    agentConfig.value = { ...props.form.agentConfig };
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
