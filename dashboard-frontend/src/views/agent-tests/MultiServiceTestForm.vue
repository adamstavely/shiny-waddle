<template>
  <div class="test-form">
    <form @submit.prevent="runTest" class="form">
      <div class="form-section">
        <h3 class="form-section-title">Agent Configuration</h3>
        <div class="form-grid">
          <div class="form-group">
            <label>Agent ID *</label>
            <input v-model="form.agentId" type="text" required class="form-input" />
          </div>
          <div class="form-group">
            <label>Agent Type *</label>
            <select v-model="form.agentType" required class="form-input">
              <option value="delegated">Delegated</option>
              <option value="direct">Direct</option>
            </select>
          </div>
        </div>
      </div>

      <div v-if="form.agentType === 'delegated'" class="form-section">
        <h3 class="form-section-title">User Context (Optional)</h3>
        <div class="form-grid">
          <div class="form-group">
            <label>User ID</label>
            <input v-model="form.userContext.userId" type="text" class="form-input" />
          </div>
          <div class="form-group">
            <label>Permissions (comma-separated)</label>
            <input v-model="permissionsInput" type="text" class="form-input" />
          </div>
        </div>
      </div>

      <div class="form-section">
        <h3 class="form-section-title">Services</h3>
        <div v-for="(service, index) in form.services" :key="index" class="service-item">
          <div class="form-grid">
            <div class="form-group">
              <label>Service ID *</label>
              <input v-model="service.serviceId" type="text" required class="form-input" />
            </div>
            <div class="form-group">
              <label>Resource ID</label>
              <input v-model="service.resource.id" type="text" class="form-input" />
            </div>
            <div class="form-group">
              <label>Resource Type</label>
              <input v-model="service.resource.type" type="text" class="form-input" />
            </div>
            <div class="form-group">
              <label>Action *</label>
              <input v-model="service.action" type="text" required class="form-input" />
            </div>
            <div class="form-group">
              <label>Expected Allowed</label>
              <select v-model="service.expectedAllowed" class="form-input">
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
import { ref } from 'vue';
import { Play } from 'lucide-vue-next';
import { useAgentTests } from '../../composables/useAgentTests';
import type { MultiServiceTestRequest } from '../../composables/useAgentTests';

const emit = defineEmits<{
  (e: 'test-complete', result: any): void;
}>();

const { loading, testMultiServiceAccess } = useAgentTests();

const form = ref<MultiServiceTestRequest>({
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

const addService = () => {
  form.value.services.push({
    serviceId: '',
    resource: { id: '', type: '' },
    action: '',
    expectedAllowed: true,
  });
};

const removeService = (index: number) => {
  form.value.services.splice(index, 1);
};

const runTest = async () => {
  if (form.value.userContext && permissionsInput.value) {
    form.value.userContext.permissions = permissionsInput.value.split(',').map(p => p.trim()).filter(p => p);
  }
  if (!form.value.userContext?.userId) {
    delete form.value.userContext;
  }
  try {
    const result = await testMultiServiceAccess(form.value);
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
  background: var(--color-bg-primary);
  border-radius: var(--border-radius-sm);
  margin-bottom: var(--spacing-md);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
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
}

.btn-primary:disabled {
  opacity: 0.6;
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
