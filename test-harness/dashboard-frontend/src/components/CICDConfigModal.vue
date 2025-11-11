<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Settings class="modal-title-icon" />
              <h2>{{ platform === 'github' ? 'GitHub Actions' : 'Jenkins' }} Configuration</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleSave">
              <!-- GitHub Actions Configuration -->
              <template v-if="platform === 'github'">
                <div class="form-group">
                  <label class="checkbox-option">
                    <input
                      v-model="form.enabled"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Enable GitHub Actions Integration</span>
                  </label>
                </div>

                <div v-if="form.enabled" class="form-section">
                  <div class="form-group">
                    <label>Repository *</label>
                    <input
                      v-model="form.repository"
                      type="text"
                      placeholder="owner/repo-name"
                      class="form-input"
                      required
                    />
                    <p class="form-help">Format: owner/repository-name</p>
                  </div>

                  <div class="form-group">
                    <label>Workflow File</label>
                    <input
                      v-model="form.workflowFile"
                      type="text"
                      placeholder=".github/workflows/compliance-tests.yml"
                      class="form-input"
                    />
                  </div>

                  <div class="form-group">
                    <label>Compliance Threshold (%) *</label>
                    <input
                      v-model.number="form.complianceThreshold"
                      type="number"
                      min="0"
                      max="100"
                      class="form-input"
                      required
                    />
                    <p class="form-help">Minimum score required to pass (0-100)</p>
                  </div>

                  <div class="form-group">
                    <label class="checkbox-option">
                      <input
                        v-model="form.blockMerges"
                        type="checkbox"
                        class="checkbox-input"
                      />
                      <span>Block merges on compliance failure</span>
                    </label>
                  </div>

                  <div class="form-group">
                    <label class="checkbox-option">
                      <input
                        v-model="form.prComments"
                        type="checkbox"
                        class="checkbox-input"
                      />
                      <span>Post comments on PRs with results</span>
                    </label>
                  </div>

                  <div class="form-group">
                    <label>GitHub Token (Secret Name)</label>
                    <input
                      v-model="form.tokenSecret"
                      type="text"
                      placeholder="GITHUB_TOKEN"
                      class="form-input"
                    />
                    <p class="form-help">Name of the GitHub Actions secret containing the token</p>
                  </div>
                </div>
              </template>

              <!-- Jenkins Configuration -->
              <template v-if="platform === 'jenkins'">
                <div class="form-group">
                  <label class="checkbox-option">
                    <input
                      v-model="form.enabled"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Enable Jenkins Integration</span>
                  </label>
                </div>

                <div v-if="form.enabled" class="form-section">
                  <div class="form-group">
                    <label>Jenkins URL *</label>
                    <input
                      v-model="form.url"
                      type="url"
                      placeholder="https://jenkins.example.com"
                      class="form-input"
                      required
                    />
                  </div>

                  <div class="form-group">
                    <label>Job Name *</label>
                    <input
                      v-model="form.jobName"
                      type="text"
                      placeholder="compliance-tests"
                      class="form-input"
                      required
                    />
                  </div>

                  <div class="form-group">
                    <label>Compliance Threshold (%) *</label>
                    <input
                      v-model.number="form.complianceThreshold"
                      type="number"
                      min="0"
                      max="100"
                      class="form-input"
                      required
                    />
                    <p class="form-help">Minimum score required to pass (0-100)</p>
                  </div>

                  <div class="form-group">
                    <label class="checkbox-option">
                      <input
                        v-model="form.blockBuilds"
                        type="checkbox"
                        class="checkbox-input"
                      />
                      <span>Block builds on compliance failure</span>
                    </label>
                  </div>

                  <div class="form-group">
                    <label>Jenkins Username</label>
                    <input
                      v-model="form.username"
                      type="text"
                      placeholder="jenkins-user"
                      class="form-input"
                    />
                  </div>

                  <div class="form-group">
                    <label>Jenkins API Token</label>
                    <input
                      v-model="form.apiToken"
                      type="password"
                      placeholder="••••••••"
                      class="form-input"
                    />
                    <p class="form-help">API token for Jenkins authentication</p>
                  </div>

                  <div class="form-group">
                    <label>Pipeline Script</label>
                    <textarea
                      v-model="form.pipelineScript"
                      class="form-textarea"
                      rows="10"
                      placeholder="Jenkinsfile or Pipeline script..."
                    ></textarea>
                    <p class="form-help">Jenkins pipeline script for compliance testing</p>
                  </div>
                </div>
              </template>

              <div class="modal-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="isSaving">
                  <Loader2 v-if="isSaving" class="btn-icon spinning" />
                  <Save v-else class="btn-icon" />
                  {{ isSaving ? 'Saving...' : 'Save Configuration' }}
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
import { Settings, X, Save, Loader2 } from 'lucide-vue-next';
import axios from 'axios';

const props = defineProps<{
  isOpen: boolean;
  platform: 'github' | 'jenkins' | null;
  config?: any;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'saved': [];
}>();

const isSaving = ref(false);

const form = ref<any>({
  enabled: false,
  // GitHub
  repository: '',
  workflowFile: '.github/workflows/compliance-tests.yml',
  complianceThreshold: 100,
  blockMerges: true,
  prComments: true,
  tokenSecret: 'GITHUB_TOKEN',
  // Jenkins
  url: '',
  jobName: '',
  blockBuilds: true,
  username: '',
  apiToken: '',
  pipelineScript: '',
});

watch(() => props.isOpen, (newVal) => {
  if (newVal && props.config) {
    form.value = { ...form.value, ...props.config };
  } else if (newVal) {
    // Reset to defaults
    form.value = {
      enabled: false,
      repository: '',
      workflowFile: '.github/workflows/compliance-tests.yml',
      complianceThreshold: 100,
      blockMerges: true,
      prComments: true,
      tokenSecret: 'GITHUB_TOKEN',
      url: '',
      jobName: '',
      blockBuilds: true,
      username: '',
      apiToken: '',
      pipelineScript: '',
    };
  }
});

const close = () => {
  emit('update:isOpen', false);
};

const handleSave = async () => {
  isSaving.value = true;
  try {
    const endpoint = props.platform === 'github'
      ? '/api/cicd/github/config'
      : '/api/cicd/jenkins/config';
    
    await axios.post(endpoint, form.value);
    emit('saved');
    close();
  } catch (error) {
    console.error('Failed to save configuration:', error);
    alert('Failed to save configuration. Please try again.');
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

.form-section {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
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

.form-input,
.form-textarea {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-textarea {
  resize: vertical;
  min-height: 120px;
}

.form-input:focus,
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

.checkbox-option {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #ffffff;
  font-size: 0.9rem;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
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

