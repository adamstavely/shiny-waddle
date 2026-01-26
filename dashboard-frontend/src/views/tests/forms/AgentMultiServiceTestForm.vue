<template>
  <div class="agent-test-form">
    <h3 class="section-title">Multi-Service Access Configuration</h3>
    
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
            <option value="delegated">Delegated</option>
            <option value="direct">Direct</option>
          </select>
        </div>
      </div>
    </div>

    <div v-if="agentConfig.agentType === 'delegated'" class="form-section">
      <h4 class="subsection-title">User Context (Optional)</h4>
      <div class="form-grid">
        <div class="form-group">
          <label>User ID</label>
          <input 
            v-model="agentConfig.userContext.userId" 
            type="text" 
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
            @input="updateForm"
          />
        </div>
      </div>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">Services</h4>
      <div v-for="(service, index) in agentConfig.services" :key="index" class="service-item">
        <div class="form-grid">
          <div class="form-group">
            <label>Service ID *</label>
            <input v-model="service.serviceId" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Resource ID</label>
            <input v-model="service.resource.id" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Resource Type</label>
            <input v-model="service.resource.type" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Action *</label>
            <input v-model="service.action" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Expected Allowed</label>
            <select v-model="service.expectedAllowed" class="form-input" @change="updateForm">
              <option :value="true">Allowed</option>
              <option :value="false">Denied</option>
            </select>
          </div>
          <div class="form-group">
            <button type="button" @click="removeService(index)" class="btn-danger btn-sm">Remove</button>
          </div>
        </div>
      </div>
      <button type="button" @click="addService" class="btn-secondary">Add Service</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import type { MultiServiceTestRequest } from '../../../composables/useAgentTests';

const props = defineProps<{
  form: any;
  isEditMode?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:form', value: any): void;
}>();

const agentConfig = ref<MultiServiceTestRequest>({
  agentId: '',
  agentType: 'delegated',
  userContext: {
    userId: '',
    permissions: [],
  },
  services: [{
    serviceId: '',
    resource: { id: '', type: '' },
    action: '',
    expectedAllowed: true,
  }],
});

const permissionsInput = ref('');

const updateForm = () => {
  if (agentConfig.value.userContext && permissionsInput.value) {
    agentConfig.value.userContext.permissions = permissionsInput.value.split(',').map(p => p.trim()).filter(p => p);
  }
  if (!agentConfig.value.userContext?.userId) {
    delete agentConfig.value.userContext;
  }
  props.form.agentConfig = agentConfig.value;
  emit('update:form', props.form);
};

const addService = () => {
  agentConfig.value.services.push({
    serviceId: '',
    resource: { id: '', type: '' },
    action: '',
    expectedAllowed: true,
  });
  updateForm();
};

const removeService = (index: number) => {
  agentConfig.value.services.splice(index, 1);
  updateForm();
};

onMounted(() => {
  if (props.form.agentConfig) {
    agentConfig.value = { ...props.form.agentConfig };
    if (agentConfig.value.userContext?.permissions) {
      permissionsInput.value = agentConfig.value.userContext.permissions.join(', ');
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
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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

.service-item {
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
