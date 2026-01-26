<template>
  <div class="agent-test-form">
    <h3 class="section-title">Dynamic Access Configuration</h3>
    
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
      <h4 class="subsection-title">Scenarios</h4>
      <div v-for="(scenario, index) in agentConfig.scenarios" :key="index" class="scenario-item">
        <h5>Scenario {{ index + 1 }}</h5>
        <div class="form-grid">
          <div class="form-group">
            <label>Name *</label>
            <input v-model="scenario.name" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>IP Address</label>
            <input v-model="scenario.context.ipAddress" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Time of Day</label>
            <input v-model="scenario.context.timeOfDay" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Location</label>
            <input v-model="scenario.context.location" type="text" class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Requested Permission *</label>
            <input v-model="scenario.requestedPermission" type="text" required class="form-input" @input="updateForm" />
          </div>
          <div class="form-group">
            <label>Expected Granted</label>
            <select v-model="scenario.expectedGranted" class="form-input" @change="updateForm">
              <option :value="true">Granted</option>
              <option :value="false">Denied</option>
            </select>
          </div>
          <div class="form-group">
            <label>JIT Access</label>
            <input v-model="scenario.jitAccess" type="checkbox" @change="updateForm" />
          </div>
          <div class="form-group">
            <button type="button" @click="removeScenario(index)" class="btn-danger btn-sm">Remove</button>
          </div>
        </div>
      </div>
      <button type="button" @click="addScenario" class="btn-secondary">Add Scenario</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import type { DynamicAccessTestRequest } from '../../../composables/useAgentTests';

const props = defineProps<{
  form: any;
  isEditMode?: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:form', value: any): void;
}>();

const agentConfig = ref<DynamicAccessTestRequest>({
  agentId: '',
  agentType: 'delegated',
  userContext: {
    userId: '',
    permissions: [],
  },
  scenarios: [{
    name: '',
    context: {},
    requestedPermission: '',
    expectedGranted: true,
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

const addScenario = () => {
  agentConfig.value.scenarios.push({
    name: '',
    context: {},
    requestedPermission: '',
    expectedGranted: true,
  });
  updateForm();
};

const removeScenario = (index: number) => {
  agentConfig.value.scenarios.splice(index, 1);
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

.scenario-item {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-sm);
  margin-bottom: var(--spacing-md);
}

.scenario-item h5 {
  margin-bottom: var(--spacing-md);
  font-weight: 600;
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
