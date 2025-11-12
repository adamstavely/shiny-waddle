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
  max-width: 700px;
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

.form-dropdown {
  width: 100%;
}

.form-textarea {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
  resize: vertical;
  min-height: 120px;
}

.form-textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-help {
  font-size: 0.75rem;
  color: #718096;
  margin-top: 4px;
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

