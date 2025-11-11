<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Database class="modal-title-icon" />
              <h2>{{ resource ? 'Edit Resource' : 'Add Resource' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body">
            <form @submit.prevent="save" class="resource-form">
              <div class="form-group">
                <label>Resource ID *</label>
                <input
                  v-model="form.id"
                  type="text"
                  placeholder="e.g., reports"
                  required
                  class="form-input"
                />
              </div>
              
              <div class="form-group">
                <label>Resource Type *</label>
                <input
                  v-model="form.type"
                  type="text"
                  placeholder="e.g., dataset, report, user"
                  required
                  class="form-input"
                />
              </div>
              
              <div class="form-group">
                <label>Sensitivity</label>
                <select v-model="form.sensitivity" class="form-input">
                  <option value="">Select sensitivity level</option>
                  <option value="public">Public</option>
                  <option value="internal">Internal</option>
                  <option value="confidential">Confidential</option>
                  <option value="restricted">Restricted</option>
                </select>
              </div>
              
              <div class="form-group">
                <label>Attributes (JSON)</label>
                <textarea
                  v-model="attributesJson"
                  placeholder='{"department": "Research", "project": "alpha"}'
                  rows="4"
                  class="form-input"
                ></textarea>
                <small>Enter attributes as JSON object</small>
              </div>
              
              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary">
                  {{ resource ? 'Update' : 'Add' }} Resource
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Database, X } from 'lucide-vue-next';
import { Teleport, Transition } from 'vue';

interface Props {
  show: boolean;
  resource?: any;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  close: [];
  save: [resource: any];
}>();

const form = ref({
  id: '',
  type: '',
  sensitivity: '',
  attributes: {} as Record<string, any>
});

const attributesJson = ref('{}');

watch(() => props.resource, (newResource) => {
  if (newResource) {
    form.value = {
      id: newResource.id || '',
      type: newResource.type || '',
      sensitivity: newResource.sensitivity || '',
      attributes: newResource.attributes || {}
    };
    attributesJson.value = JSON.stringify(newResource.attributes || {}, null, 2);
  } else {
    form.value = {
      id: '',
      type: '',
      sensitivity: '',
      attributes: {}
    };
    attributesJson.value = '{}';
  }
}, { immediate: true });

const close = () => {
  emit('close');
};

const save = () => {
  try {
    form.value.attributes = JSON.parse(attributesJson.value || '{}');
  } catch (error) {
    alert('Invalid JSON in attributes field');
    return;
  }
  
  emit('save', { ...form.value });
  close();
};
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
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.resource-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-input {
  padding: 12px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-input textarea {
  resize: vertical;
  font-family: 'Courier New', monospace;
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-primary {
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

