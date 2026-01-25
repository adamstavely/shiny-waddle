<template>
  <div class="templates-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Policy Templates</h1>
          <p class="page-description">Create policies from pre-built templates for common use cases</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create from Template
        </button>
      </div>
    </div>

    <!-- Templates Grid -->
    <div v-if="loading" class="loading-state">
      <div class="spinner"></div>
      <p>Loading templates...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertCircle class="icon" />
      <p>{{ error }}</p>
      <button @click="loadTemplates" class="btn-primary">Retry</button>
    </div>

    <div v-else class="templates-grid">
      <div
        v-for="template in templates"
        :key="template.name"
        class="template-card"
        @click="viewTemplate(template.name)"
      >
        <div class="template-header">
          <div class="template-icon">
            <Shield v-if="template.name === 'rbac'" />
            <Key v-else-if="template.name === 'abac'" />
            <HeartPulse v-else-if="template.name === 'hipaa'" />
            <Globe v-else-if="template.name === 'gdpr'" />
            <FileText v-else />
          </div>
          <h3 class="template-name">{{ template.displayName }}</h3>
        </div>
        <p class="template-description">{{ template.description }}</p>
        <div class="template-actions" @click.stop>
          <button 
            type="button" 
            @click="previewTemplate(template.name)" 
            class="action-btn"
          >
            Preview
          </button>
          <button 
            type="button" 
            @click="createFromTemplate(template.name)" 
            class="btn-primary"
          >
            Use Template
          </button>
        </div>
      </div>
    </div>

    <!-- Template Preview Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="previewTemplateName" class="modal-overlay" @click="previewTemplateName = null">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Template Preview: {{ previewTemplateName?.toUpperCase() }}</h2>
              <button @click="previewTemplateName = null" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="previewLoading" class="loading-state">
                <div class="spinner"></div>
              </div>
              <div v-else-if="previewError" class="error-state">
                <p>{{ previewError }}</p>
              </div>
              <div v-else-if="previewData" class="template-preview">
                <div class="preview-section">
                  <h3>Description</h3>
                  <pre class="description-text">{{ previewData.fullDescription }}</pre>
                </div>
                <div class="preview-section">
                  <h3>Configuration Schema</h3>
                  <pre class="schema-text">{{ JSON.stringify(previewData.configSchema, null, 2) }}</pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Create from Template Modal -->
    <CreateFromTemplateModal
      v-if="showCreateModal || selectedTemplate"
      :template-name="selectedTemplate || ''"
      @close="showCreateModal = false; selectedTemplate = null"
      @created="handlePolicyCreated"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import {
  Shield,
  Key,
  HeartPulse,
  Globe,
  FileText,
  Plus,
  AlertCircle,
  X,
} from 'lucide-vue-next';
import { Teleport, Transition } from 'vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import CreateFromTemplateModal from '../components/templates/CreateFromTemplateModal.vue';
import { useTemplates, type Template, type TemplateDetail } from '../composables/useTemplates';
import { useApiDataAuto } from '../composables/useApiData';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Templates' },
];

const { listTemplates: fetchTemplates, getTemplate: fetchTemplate } = useTemplates();
const showCreateModal = ref(false);
const selectedTemplate = ref<string | null>(null);
const previewTemplateName = ref<string | null>(null);
const previewData = ref<TemplateDetail | null>(null);
const previewLoading = ref(false);
const previewError = ref<string | null>(null);

const { data: templates, loading, error, reload: loadTemplates } = useApiDataAuto(
  async () => {
    return await fetchTemplates();
  },
  {
    initialData: [],
    errorMessage: 'Failed to load templates',
  }
);

const viewTemplate = (name: string) => {
  selectedTemplate.value = name;
  showCreateModal.value = true;
};

const previewTemplate = async (name: string) => {
  previewTemplateName.value = name;
  previewLoading.value = true;
  previewError.value = null;
  previewData.value = null;
  try {
    previewData.value = await fetchTemplate(name);
  } catch (err: any) {
    previewError.value = err.message || 'Failed to load template preview';
  } finally {
    previewLoading.value = false;
  }
};

const createFromTemplate = (name: string) => {
  selectedTemplate.value = name;
  showCreateModal.value = true;
};

const handlePolicyCreated = () => {
  showCreateModal.value = false;
  selectedTemplate.value = null;
  // Optionally reload templates or show success message
};
</script>

<style scoped>
.templates-page {
  padding: 2rem;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: #ffffff;
}

.page-description {
  color: #a0aec0;
  font-size: 1rem;
}

.templates-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 1.5rem;
}

.template-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.template-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.2);
}

.template-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
}

.template-icon {
  width: 48px;
  height: 48px;
  border-radius: 8px;
  background: rgba(79, 172, 254, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #4facfe;
  flex-shrink: 0;
}

.template-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.template-description {
  color: #a0aec0;
  margin-bottom: 1rem;
  line-height: 1.5;
}

.template-actions {
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.template-preview {
  max-height: 60vh;
  overflow-y: auto;
}

.preview-section {
  margin-bottom: 2rem;
}

.preview-section h3 {
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: #ffffff;
}

.description-text,
.schema-text {
  background: rgba(26, 31, 46, 0.6);
  padding: 1rem;
  border-radius: 4px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  font-family: 'Courier New', monospace;
  font-size: 0.9rem;
  white-space: pre-wrap;
  word-wrap: break-word;
  color: #a0aec0;
}

.loading-state,
.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  gap: 1rem;
}

.loading-state p,
.error-state p {
  color: #a0aec0;
}

.error-state {
  color: #fc8181;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

.btn-primary .btn-icon {
  width: 16px;
  height: 16px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  max-width: 90vw;
  max-height: 90vh;
  overflow: auto;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  display: flex;
  flex-direction: column;
  min-width: 600px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.modal-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #a0aec0;
  transition: color 0.2s;
}

.modal-close:hover {
  color: #ffffff;
}

.modal-body {
  padding: 1.5rem;
  flex: 1;
  overflow-y: auto;
}

.close-icon {
  width: 20px;
  height: 20px;
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
