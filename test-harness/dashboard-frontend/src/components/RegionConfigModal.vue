<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Globe class="modal-title-icon" />
              <h2>{{ region ? 'Edit Region' : 'Add Region' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleSave">
              <div class="form-group">
                <label>Region ID *</label>
                <input
                  v-model="form.id"
                  type="text"
                  placeholder="e.g., us-east-1"
                  class="form-input"
                  required
                />
              </div>

              <div class="form-group">
                <label>Region Name *</label>
                <input
                  v-model="form.name"
                  type="text"
                  placeholder="e.g., US East (Virginia)"
                  class="form-input"
                  required
                />
              </div>

              <div class="form-group">
                <label>Endpoint *</label>
                <input
                  v-model="form.endpoint"
                  type="url"
                  placeholder="https://api.example.com"
                  class="form-input"
                  required
                />
              </div>

              <div class="form-group">
                <label>PDP Endpoint</label>
                <input
                  v-model="form.pdpEndpoint"
                  type="url"
                  placeholder="https://pdp.example.com/v1/evaluate"
                  class="form-input"
                />
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label>Timezone</label>
                  <input
                    v-model="form.timezone"
                    type="text"
                    placeholder="America/New_York"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Latency (ms)</label>
                  <input
                    v-model.number="form.latency"
                    type="number"
                    min="0"
                    placeholder="50"
                    class="form-input"
                  />
                </div>
              </div>

              <div class="modal-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="isSaving">
                  <Loader2 v-if="isSaving" class="btn-icon spinning" />
                  <Save v-else class="btn-icon" />
                  {{ isSaving ? 'Saving...' : 'Save Region' }}
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
import { ref, watch } from 'vue';
import { Teleport } from 'vue';
import { Globe, X, Save, Loader2 } from 'lucide-vue-next';
import axios from 'axios';

const props = defineProps<{
  isOpen: boolean;
  region?: any;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'saved': [];
}>();

const isSaving = ref(false);

const form = ref({
  id: '',
  name: '',
  endpoint: '',
  pdpEndpoint: '',
  timezone: '',
  latency: undefined as number | undefined,
});

watch(() => props.isOpen, (newVal) => {
  if (newVal) {
    if (props.region) {
      form.value = {
        id: props.region.id || '',
        name: props.region.name || '',
        endpoint: props.region.endpoint || '',
        pdpEndpoint: props.region.pdpEndpoint || '',
        timezone: props.region.timezone || '',
        latency: props.region.latency,
      };
    } else {
      form.value = {
        id: '',
        name: '',
        endpoint: '',
        pdpEndpoint: '',
        timezone: '',
        latency: undefined,
      };
    }
  }
});

const close = () => {
  emit('update:isOpen', false);
};

const handleSave = async () => {
  isSaving.value = true;
  try {
    if (props.region) {
      await axios.patch(`/api/distributed-systems/regions/${props.region.id}`, form.value);
    } else {
      await axios.post('/api/distributed-systems/regions', form.value);
    }
    emit('saved');
    close();
  } catch (error) {
    console.error('Failed to save region:', error);
    alert('Failed to save region. Please try again.');
  } finally {
    isSaving.value = false;
  }
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

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-input {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
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

