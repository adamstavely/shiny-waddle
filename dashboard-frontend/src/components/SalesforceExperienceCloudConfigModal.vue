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
                <label>Name *</label>
                <input v-model="formData.name" type="text" required class="form-input" />
              </div>

              <div class="form-group">
                <label>URL *</label>
                <input v-model="formData.url" type="url" required class="form-input" placeholder="https://example.force.com" />
              </div>

              <div class="form-group">
                <label>Cookies (for authenticated tests)</label>
                <textarea
                  v-model="formData.cookies"
                  class="form-input"
                  rows="3"
                  placeholder="sid=...;"
                ></textarea>
              </div>

              <div class="form-group">
                <label>App Path</label>
                <input v-model="formData.app" type="text" class="form-input" placeholder="/myApp" />
              </div>

              <div class="form-group">
                <label>Aura Path</label>
                <input v-model="formData.aura" type="text" class="form-input" placeholder="/aura" />
              </div>

              <div class="form-group">
                <label>Object List (comma-separated)</label>
                <input
                  v-model="objectListString"
                  type="text"
                  class="form-input"
                  placeholder="Account, Contact, Opportunity"
                />
                <small class="form-hint">Leave empty to test all objects</small>
              </div>

              <div class="form-group">
                <label>Timeout (ms)</label>
                <input v-model.number="formData.timeout" type="number" class="form-input" placeholder="300000" />
                <small class="form-hint">Default: 300000 (5 minutes)</small>
              </div>

              <div class="form-group">
                <label>
                  <input v-model="formData.noGraphQL" type="checkbox" />
                  Disable GraphQL checks
                </label>
              </div>

              <div class="form-group">
                <label>
                  <input v-model="formData.insecure" type="checkbox" />
                  Ignore TLS certificate validation
                </label>
              </div>

              <div class="form-group">
                <label>Python Path</label>
                <input v-model="formData.pythonPath" type="text" class="form-input" placeholder="python3" />
                <small class="form-hint">Default: python3</small>
              </div>

              <div class="form-group">
                <label>Aura Inspector Path</label>
                <input
                  v-model="formData.auraInspectorPath"
                  type="text"
                  class="form-input"
                  placeholder="aura_cli.py (leave empty to use PATH)"
                />
              </div>

              <div class="form-actions">
                <button type="button" @click="$emit('close')" class="cancel-btn">Cancel</button>
                <button type="submit" class="save-btn" :disabled="saving">
                  {{ saving ? 'Saving...' : 'Save' }}
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
import { ref, watch, computed } from 'vue';
import { X } from 'lucide-vue-next';
import axios from 'axios';
import type { SalesforceExperienceCloudConfigEntity } from '../types/salesforce-experience-cloud';

interface Props {
  show: boolean;
  config: SalesforceExperienceCloudConfigEntity | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [];
}>();

const saving = ref(false);
const formData = ref({
  name: '',
  url: '',
  cookies: '',
  app: '',
  aura: '',
  objectList: [] as string[],
  timeout: 300000,
  noGraphQL: false,
  insecure: false,
  pythonPath: 'python3',
  auraInspectorPath: '',
});

const objectListString = computed({
  get: () => formData.value.objectList?.join(', ') || '',
  set: (value: string) => {
    formData.value.objectList = value
      ? value.split(',').map(s => s.trim()).filter(s => s.length > 0)
      : [];
  },
});

watch(
  () => props.config,
  (newConfig) => {
    if (newConfig) {
      formData.value = {
        name: newConfig.name,
        url: newConfig.url,
        cookies: newConfig.cookies || '',
        app: newConfig.app || '',
        aura: newConfig.aura || '',
        objectList: newConfig.objectList || [],
        timeout: newConfig.timeout || 300000,
        noGraphQL: newConfig.noGraphQL || false,
        insecure: newConfig.insecure || false,
        pythonPath: newConfig.pythonPath || 'python3',
        auraInspectorPath: newConfig.auraInspectorPath || '',
      };
    } else {
      formData.value = {
        name: '',
        url: '',
        cookies: '',
        app: '',
        aura: '',
        objectList: [],
        timeout: 300000,
        noGraphQL: false,
        insecure: false,
        pythonPath: 'python3',
        auraInspectorPath: '',
      };
    }
  },
  { immediate: true }
);

const handleSubmit = async () => {
  saving.value = true;
  try {
    const payload: any = {
      name: formData.value.name,
      url: formData.value.url,
    };

    if (formData.value.cookies) payload.cookies = formData.value.cookies;
    if (formData.value.app) payload.app = formData.value.app;
    if (formData.value.aura) payload.aura = formData.value.aura;
    if (formData.value.objectList.length > 0) payload.objectList = formData.value.objectList;
    if (formData.value.timeout) payload.timeout = formData.value.timeout;
    if (formData.value.noGraphQL) payload.noGraphQL = formData.value.noGraphQL;
    if (formData.value.insecure) payload.insecure = formData.value.insecure;
    if (formData.value.pythonPath) payload.pythonPath = formData.value.pythonPath;
    if (formData.value.auraInspectorPath) payload.auraInspectorPath = formData.value.auraInspectorPath;

    if (props.config) {
      await axios.patch(`/api/salesforce-experience-cloud/configs/${props.config.id}`, payload);
    } else {
      await axios.post('/api/salesforce-experience-cloud/configs', payload);
    }

    emit('save');
  } catch (error: any) {
    console.error('Error saving configuration:', error);
    alert(error.response?.data?.message || 'Failed to save configuration');
  } finally {
    saving.value = false;
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
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: var(--card-bg);
  border-radius: 8px;
  max-width: 600px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid var(--border-color);
}

.modal-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.modal-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  color: var(--text-secondary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 20px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 6px;
  font-size: 14px;
  font-weight: 500;
  color: var(--text-primary);
}

.form-group label input[type="checkbox"] {
  margin-right: 8px;
}

.form-input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 14px;
  font-family: inherit;
}

.form-input:focus {
  outline: none;
  border-color: var(--primary-color);
}

.form-hint {
  display: block;
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-secondary);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--border-color);
}

.cancel-btn,
.save-btn {
  padding: 10px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.cancel-btn {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
}

.cancel-btn:hover {
  background: var(--bg-tertiary);
}

.save-btn {
  background: var(--primary-color);
  color: white;
}

.save-btn:hover:not(:disabled) {
  background: var(--primary-color-dark);
}

.save-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
