<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>{{ endpoint ? 'Edit Endpoint' : 'New Endpoint' }}</h2>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleSubmit">
              <div class="form-group">
                <label>Name</label>
                <input v-model="formData.name" type="text" required class="form-input" />
              </div>

              <div class="form-group">
                <label>Endpoint Path</label>
                <input v-model="formData.endpoint" type="text" required class="form-input" placeholder="/api/v1/users" />
              </div>

              <div class="form-group">
                <label>HTTP Method</label>
                <select v-model="formData.method" required class="form-input">
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                  <option value="OPTIONS">OPTIONS</option>
                </select>
              </div>

              <div class="form-group">
                <label>API Type</label>
                <select v-model="formData.apiType" required class="form-input">
                  <option value="rest">REST</option>
                  <option value="graphql">GraphQL</option>
                  <option value="authentication">Authentication</option>
                  <option value="authorization">Authorization</option>
                  <option value="rate-limiting">Rate Limiting</option>
                  <option value="vulnerability">Vulnerability</option>
                </select>
              </div>

              <div class="form-group">
                <label>Expected Status Code</label>
                <input v-model.number="formData.expectedStatus" type="number" class="form-input" />
              </div>

              <div class="form-group">
                <label>
                  <input v-model="formData.expectedAuthRequired" type="checkbox" />
                  Authentication Required
                </label>
              </div>

              <div class="form-group">
                <label>
                  <input v-model="formData.expectedRateLimit" type="checkbox" />
                  Rate Limiting Expected
                </label>
              </div>

              <div class="form-group">
                <label>Request Body (JSON)</label>
                <textarea
                  v-model="bodyJson"
                  class="form-input"
                  rows="4"
                  placeholder='{"key": "value"}'
                ></textarea>
              </div>

              <div class="form-actions">
                <button type="button" @click="$emit('close')" class="cancel-btn">Cancel</button>
                <button type="submit" class="save-btn">Save</button>
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
import { X } from 'lucide-vue-next';
import type { APIEndpointEntity } from '../types/api-security';

interface Props {
  show: boolean;
  endpoint: APIEndpointEntity | null;
  configId: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [endpoint: APIEndpointEntity];
}>();

const formData = ref({
  name: '',
  endpoint: '',
  method: 'GET' as any,
  apiType: 'rest' as any,
  expectedStatus: undefined as number | undefined,
  expectedAuthRequired: false,
  expectedRateLimit: false,
  body: undefined as any,
});

const bodyJson = ref('');

watch(() => props.endpoint, (newEndpoint) => {
  if (newEndpoint) {
    formData.value = {
      name: newEndpoint.name,
      endpoint: newEndpoint.endpoint,
      method: newEndpoint.method,
      apiType: newEndpoint.apiType,
      expectedStatus: newEndpoint.expectedStatus,
      expectedAuthRequired: newEndpoint.expectedAuthRequired || false,
      expectedRateLimit: newEndpoint.expectedRateLimit || false,
      body: newEndpoint.body,
    };
    bodyJson.value = newEndpoint.body ? JSON.stringify(newEndpoint.body, null, 2) : '';
  } else {
    formData.value = {
      name: '',
      endpoint: '',
      method: 'GET',
      apiType: 'rest',
      expectedStatus: undefined,
      expectedAuthRequired: false,
      expectedRateLimit: false,
      body: undefined,
    };
    bodyJson.value = '';
  }
}, { immediate: true });

const handleSubmit = () => {
  try {
    const body = bodyJson.value ? JSON.parse(bodyJson.value) : undefined;
    
    const endpointData: any = {
      configId: props.configId,
      ...formData.value,
      body,
    };

    if (props.endpoint) {
      endpointData.id = props.endpoint.id;
    }

    emit('save', endpointData as APIEndpointEntity);
    emit('close');
  } catch (error) {
    console.error('Error parsing body:', error);
    alert('Invalid JSON in request body');
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
  background: rgba(0, 0, 0, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 8px;
  transition: all 0.2s;
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
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
  margin-bottom: 8px;
}

.form-group label input[type="checkbox"] {
  margin-right: 8px;
}

.form-input {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-family: inherit;
  transition: all 0.2s;
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

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.cancel-btn,
.save-btn {
  padding: 10px 24px;
  border-radius: 8px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.cancel-btn {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.cancel-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.save-btn {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  color: #ffffff;
}

.save-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

