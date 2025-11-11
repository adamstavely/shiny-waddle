<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>{{ config ? 'Edit Configuration' : 'New Configuration' }}</h2>
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
                <label>Base URL</label>
                <input v-model="formData.baseUrl" type="url" required class="form-input" />
              </div>

              <div class="form-group">
                <label>Timeout (ms)</label>
                <input v-model.number="formData.timeout" type="number" class="form-input" />
              </div>

              <div class="form-section">
                <h3>Authentication</h3>
                <div class="form-group">
                  <label>Type</label>
                  <select v-model="formData.authentication.type" class="form-input">
                    <option value="">None</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="basic">Basic Auth</option>
                    <option value="oauth2">OAuth2</option>
                    <option value="api-key">API Key</option>
                    <option value="jwt">JWT</option>
                  </select>
                </div>
                <div v-if="formData.authentication.type" class="form-group">
                  <label>Credentials (JSON)</label>
                  <textarea
                    v-model="credentialsJson"
                    class="form-input"
                    rows="4"
                    placeholder='{"token": "..."}'
                  ></textarea>
                </div>
              </div>

              <div class="form-section">
                <h3>Rate Limiting</h3>
                <div class="form-group">
                  <label>Max Requests</label>
                  <input v-model.number="formData.rateLimitConfig.maxRequests" type="number" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Window (seconds)</label>
                  <input v-model.number="formData.rateLimitConfig.windowSeconds" type="number" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Strategy</label>
                  <select v-model="formData.rateLimitConfig.strategy" class="form-input">
                    <option value="fixed">Fixed</option>
                    <option value="sliding">Sliding</option>
                    <option value="token-bucket">Token Bucket</option>
                  </select>
                </div>
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
import { ref, watch, computed } from 'vue';
import { X } from 'lucide-vue-next';
import type { APISecurityTestConfigEntity } from '../types/api-security';

interface Props {
  show: boolean;
  config: APISecurityTestConfigEntity | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [config: APISecurityTestConfigEntity];
}>();

const formData = ref({
  name: '',
  baseUrl: '',
  timeout: 5000,
  authentication: {
    type: '',
    credentials: {} as Record<string, string>,
  },
  rateLimitConfig: {
    maxRequests: 100,
    windowSeconds: 60,
    strategy: 'fixed' as 'fixed' | 'sliding' | 'token-bucket',
  },
});

const credentialsJson = ref('{}');

watch(() => props.config, (newConfig) => {
  if (newConfig) {
    formData.value = {
      name: newConfig.name,
      baseUrl: newConfig.baseUrl,
      timeout: newConfig.timeout || 5000,
      authentication: newConfig.authentication || { type: '', credentials: {} },
      rateLimitConfig: newConfig.rateLimitConfig || {
        maxRequests: 100,
        windowSeconds: 60,
        strategy: 'fixed',
      },
    };
    credentialsJson.value = JSON.stringify(newConfig.authentication?.credentials || {}, null, 2);
  } else {
    formData.value = {
      name: '',
      baseUrl: '',
      timeout: 5000,
      authentication: { type: '', credentials: {} },
      rateLimitConfig: { maxRequests: 100, windowSeconds: 60, strategy: 'fixed' },
    };
    credentialsJson.value = '{}';
  }
}, { immediate: true });

const handleSubmit = async () => {
  try {
    const credentials = JSON.parse(credentialsJson.value || '{}');
    
    const configData: any = {
      ...formData.value,
      authentication: formData.value.authentication.type
        ? { type: formData.value.authentication.type, credentials }
        : undefined,
      rateLimitConfig: formData.value.rateLimitConfig.maxRequests
        ? formData.value.rateLimitConfig
        : undefined,
    };

    if (props.config) {
      configData.id = props.config.id;
    }

    emit('save', configData as APISecurityTestConfigEntity);
    emit('close');
  } catch (error) {
    console.error('Error parsing credentials:', error);
    alert('Invalid JSON in credentials field');
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

.form-section {
  margin-bottom: 24px;
  padding-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.form-section:last-child {
  border-bottom: none;
}

.form-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
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

