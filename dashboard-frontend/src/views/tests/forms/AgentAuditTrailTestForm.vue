<template>
  <div class="agent-test-form">
    <h3 class="section-title">Audit Trail Validation Configuration</h3>
    
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
        <div class="form-group">
          <label>User ID (Optional)</label>
          <input 
            v-model="agentConfig.userId" 
            type="text" 
            class="form-input"
            @input="updateForm"
          />
        </div>
      </div>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">Expected Actions</h4>
      <div v-for="(action, index) in agentConfig.actions" :key="index" class="action-item">
        <div class="form-grid">
          <div class="form-group">
            <label>Service ID *</label>
            <input v-model="action.serviceId" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Action *</label>
            <input v-model="action.action" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Resource ID *</label>
            <input v-model="action.resourceId" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Resource Type *</label>
            <input v-model="action.resourceType" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Timestamp</label>
            <input v-model="action.timestamp" type="datetime-local" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Expected Logged</label>
            <select v-model="action.expectedLogged" class="form-input" @change="updateForm">
              <option :value="true">Yes</option>
              <option :value="false">No</option>
            </select>
          </div>
          <div class="form-group">
            <button type="button" @click="removeAction(index)" class="btn-danger btn-sm">Remove</button>
          </div>
        </div>
      </div>
      <button type="button" @click="addAction" class="btn-secondary">Add Action</button>
    </div>

    <div class="form-section">
      <h4 class="subsection-title">Validation Options</h4>
      <div class="form-grid">
        <div class="form-group">
          <label>Audit Sources (comma-separated)</label>
          <input 
            v-model="auditSourcesInput" 
            type="text" 
            class="form-input"
            @input="updateForm"
          />
        </div>
        <div class="form-group">
          <label>Retention Period (days)</label>
          <input 
            v-model.number="agentConfig.retentionPeriod" 
            type="number" 
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
import type { AuditTrailValidationRequest } from '../../../composables/useAgentTests';

const props = defineProps<{
  form: any;
  isEditMode?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:form', value: any): void;
}>();

const agentConfig = ref<AuditTrailValidationRequest>({
  agentId: '',
  agentType: 'delegated',
  actions: [{
    serviceId: '',
    action: '',
    resourceId: '',
    resourceType: '',
    timestamp: new Date(),
    expectedLogged: true,
  }],
});

const auditSourcesInput = ref('');

const updateForm = () => {
  if (auditSourcesInput.value) {
    agentConfig.value.auditSources = auditSourcesInput.value.split(',').map(s => s.trim()).filter(s => s);
  }
  props.form.agentConfig = agentConfig.value;
  emit('update:form', props.form);
};

const addAction = () => {
  agentConfig.value.actions.push({
    serviceId: '',
    action: '',
    resourceId: '',
    resourceType: '',
    timestamp: new Date(),
    expectedLogged: true,
  });
  updateForm();
};

const removeAction = (index: number) => {
  agentConfig.value.actions.splice(index, 1);
  updateForm();
};

onMounted(() => {
  if (props.form.agentConfig) {
    agentConfig.value = { ...props.form.agentConfig };
    if (agentConfig.value.auditSources) {
      auditSourcesInput.value = agentConfig.value.auditSources.join(', ');
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

.action-item {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-sm);
  margin-bottom: var(--spacing-md);
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
