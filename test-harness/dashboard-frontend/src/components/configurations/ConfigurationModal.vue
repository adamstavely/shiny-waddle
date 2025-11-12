<template>
  <div v-if="show" class="modal-overlay" @click.self="close">
    <div class="modal-content">
      <div class="modal-header">
        <div class="modal-header-title">
          <Settings class="modal-header-icon" />
          <h2>{{ editingConfig ? 'Edit Configuration' : 'Create Configuration' }}</h2>
        </div>
        <button @click="close" class="close-btn">×</button>
      </div>
      <div class="modal-body">
        <div v-if="!editingConfig" class="type-selector">
          <label>Configuration Type</label>
          <select v-model="selectedType" @change="onTypeChange">
            <option value="">Select a type...</option>
            <option value="rls-cls">RLS/CLS</option>
            <option value="network-policy">Network Policy</option>
            <option value="dlp">DLP</option>
            <option value="identity-lifecycle">Identity Lifecycle</option>
            <option value="api-gateway">API Gateway</option>
            <option value="distributed-systems">Distributed Systems</option>
          </select>
        </div>

        <div v-if="selectedType || editingConfig" class="form-container">
          <div class="form-section">
            <label>Name *</label>
            <input v-model="formData.name" type="text" required />
          </div>
          <div class="form-section">
            <label>Description</label>
            <textarea v-model="formData.description" rows="3"></textarea>
          </div>

          <component
            :is="configFormComponent"
            v-if="configFormComponent"
            :config="editingConfig"
            v-model="formData"
          />
        </div>
      </div>
      <div class="modal-footer">
        <button @click="close" class="btn-secondary">Cancel</button>
        <button @click="save" class="btn-primary" :disabled="!canSave">Save</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Settings } from 'lucide-vue-next';
import RLSCLSConfigForm from './RLSCLSConfigForm.vue';
import NetworkPolicyConfigForm from './NetworkPolicyConfigForm.vue';
import DLPConfigForm from './DLPConfigForm.vue';
import IdentityLifecycleConfigForm from './IdentityLifecycleConfigForm.vue';
import APIGatewayConfigForm from './APIGatewayConfigForm.vue';
import DistributedSystemsConfigForm from './DistributedSystemsConfigForm.vue';

const props = defineProps<{
  show: boolean;
  config?: any;
  type?: string;
}>();

const emit = defineEmits<{
  close: [];
  save: [config: any];
}>();

const selectedType = ref(props.type || props.config?.type || '');
const formData = ref<any>({
  name: '',
  description: '',
  type: selectedType.value,
  ...(props.config || {})
});

const configFormComponent = computed(() => {
  const type = selectedType.value || props.config?.type;
  const components: Record<string, any> = {
    'rls-cls': RLSCLSConfigForm,
    'network-policy': NetworkPolicyConfigForm,
    'dlp': DLPConfigForm,
    'identity-lifecycle': IdentityLifecycleConfigForm,
    'api-gateway': APIGatewayConfigForm,
    'distributed-systems': DistributedSystemsConfigForm,
  };
  return components[type || ''];
});

const canSave = computed(() => {
  return formData.value.name && (selectedType.value || props.config?.type);
});

const onTypeChange = () => {
  formData.value.type = selectedType.value;
  // Reset form data when type changes
  formData.value = {
    name: formData.value.name,
    description: formData.value.description,
    type: selectedType.value,
  };
};

const close = () => {
  emit('close');
};

const save = () => {
  emit('save', { ...formData.value, type: selectedType.value || props.config?.type });
};

watch(() => props.config, (newConfig) => {
  if (newConfig) {
    formData.value = { ...newConfig };
    selectedType.value = newConfig.type;
  }
}, { immediate: true });
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 90%;
  max-width: 800px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.modal-header-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  color: #ffffff;
  font-weight: 600;
}

.close-btn {
  background: transparent;
  border: none;
  font-size: 2rem;
  cursor: pointer;
  color: #a0aec0;
  line-height: 1;
  padding: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  transition: all 0.2s;
}

.close-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.modal-body {
  padding: 1.5rem;
  overflow-y: auto;
  flex: 1;
}

.type-selector {
  margin-bottom: 1.5rem;
}

.type-selector label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: #a0aec0;
  font-size: 0.9rem;
}

.type-selector select {
  width: 100%;
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 1rem;
  color: #ffffff;
  transition: all 0.2s;
}

.type-selector select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.type-selector select option {
  background: #1a1f2e;
  color: #ffffff;
}

.form-container {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-section label {
  font-weight: 500;
  color: #a0aec0;
  font-size: 0.9rem;
}

.form-section input,
.form-section textarea {
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 1rem;
  color: #ffffff;
  transition: all 0.2s;
}

.form-section input:focus,
.form-section textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-section input::placeholder,
.form-section textarea::placeholder {
  color: #718096;
}

.form-section textarea {
  resize: vertical;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  padding: 1.5rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-secondary {
  padding: 0.75rem 1.5rem;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  color: #4facfe;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-primary {
  padding: 0.75rem 1.5rem;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  transition: all 0.2s;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>

