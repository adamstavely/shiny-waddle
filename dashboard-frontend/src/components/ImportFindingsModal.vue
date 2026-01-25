<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Upload class="modal-title-icon" />
              <h2>Import Findings</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleImport">
              <div class="form-group">
                <label>Scanner *</label>
                <Dropdown
                  v-model="form.scannerId"
                  :options="scannerOptions"
                  placeholder="Select scanner"
                  class="form-dropdown"
                />
              </div>

              <div class="form-group">
                <label>Source Type *</label>
                <Dropdown
                  v-model="form.source"
                  :options="sourceOptions"
                  placeholder="Select source type"
                  class="form-dropdown"
                />
              </div>

              <div class="form-group">
                <label>Findings Data (JSON) *</label>
                <textarea
                  v-model="form.findingsData"
                  class="form-textarea"
                  rows="15"
                  placeholder='Paste JSON findings from scanner...'
                ></textarea>
                <p class="form-help">Paste the raw JSON output from your scanner</p>
              </div>

              <div class="form-group">
                <label>Metadata (Optional)</label>
                <textarea
                  v-model="form.metadata"
                  class="form-textarea"
                  rows="5"
                  placeholder='{"applicationId": "my-app", "team": "platform"}'
                ></textarea>
                <p class="form-help">Additional metadata to enrich findings</p>
              </div>

              <div class="modal-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="isImporting">
                  <Loader2 v-if="isImporting" class="btn-icon spinning" />
                  <Upload v-else class="btn-icon" />
                  {{ isImporting ? 'Importing...' : 'Import Findings' }}
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
import { Upload, X, Loader2 } from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from './Dropdown.vue';

const props = defineProps<{
  isOpen: boolean;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'imported': [];
}>();

const isImporting = ref(false);

const form = ref({
  scannerId: '',
  source: '',
  findingsData: '',
  metadata: '',
});

const scannerOptions = [
  { label: 'SonarQube', value: 'sonarqube' },
  { label: 'Snyk (SCA)', value: 'snyk' },
  { label: 'Snyk Container', value: 'snyk-container' },
  { label: 'OWASP ZAP', value: 'owasp-zap' },
  { label: 'Checkov', value: 'checkov' },
  { label: 'Trivy', value: 'trivy' },
  { label: 'AWS Security Hub', value: 'aws-security-hub' },
];

const sourceOptions = [
  { label: 'SAST', value: 'sast' },
  { label: 'DAST', value: 'dast' },
  { label: 'SCA', value: 'sca' },
  { label: 'IaC', value: 'iac' },
  { label: 'Container', value: 'container' },
  { label: 'CSPM', value: 'cspm' },
];

watch(() => props.isOpen, (newVal) => {
  if (newVal) {
    form.value = {
      scannerId: '',
      source: '',
      findingsData: '',
      metadata: '',
    };
  }
});

const close = () => {
  emit('update:isOpen', false);
};

const handleImport = async () => {
  if (!form.value.scannerId || !form.value.source || !form.value.findingsData) {
    alert('Please fill in all required fields');
    return;
  }

  isImporting.value = true;
  try {
    let findings: any[];
    try {
      findings = JSON.parse(form.value.findingsData);
    } catch (error) {
      alert('Invalid JSON format. Please check your findings data.');
      return;
    }

    let metadata: Record<string, any> = {};
    if (form.value.metadata) {
      try {
        metadata = JSON.parse(form.value.metadata);
      } catch (error) {
        console.warn('Invalid metadata JSON, ignoring');
      }
    }

    const scannerResult = {
      scannerId: form.value.scannerId,
      source: form.value.source,
      findings: Array.isArray(findings) ? findings : [findings],
      metadata,
    };

    await axios.post('/api/unified-findings/normalize', [scannerResult]);
    emit('imported');
    close();
  } catch (error: any) {
    console.error('Failed to import findings:', error);
    alert(`Failed to import findings: ${error.response?.data?.message || error.message}`);
  } finally {
    isImporting.value = false;
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
  background: var(--color-bg-overlay-dark);
  opacity: 0.6;
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-lg);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 700px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.modal-header h2 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-sm);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
}

.form-dropdown {
  width: 100%;
}

.form-textarea {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-dark);
  opacity: 0.6;
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-family: 'Courier New', monospace;
  resize: vertical;
  min-height: 120px;
}

.form-textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.form-help {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin-top: 4px;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-2xl);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  font-size: var(--font-size-base);
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.3;
  color: var(--color-primary);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
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

