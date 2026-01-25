<template>
  <div class="batch-operations-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Batch Operations</h1>
          <p class="page-description">Run multiple operations (tests, validation, reports) from a batch file</p>
        </div>
        <button @click="showUploadModal = true" class="btn-primary">
          <Upload class="btn-icon" />
          Upload Batch File
        </button>
      </div>
    </div>

    <!-- Batch File Editor -->
    <div class="batch-editor-section">
      <div class="section-header">
        <h2>Batch File Editor</h2>
        <div class="section-actions">
          <select v-model="fileFormat" class="format-select">
            <option value="json">JSON</option>
            <option value="yaml">YAML</option>
          </select>
          <button @click="loadExample" class="action-btn">Load Example</button>
          <button @click="validateFile" class="action-btn">Validate</button>
        </div>
      </div>

      <div class="editor-container">
        <textarea
          v-model="batchFileContent"
          class="batch-editor"
          placeholder="Paste or type your batch file content here..."
        ></textarea>
      </div>

      <div class="editor-actions">
        <button @click="runAllOperations" :disabled="running" class="btn-primary">
          <Play v-if="!running" class="btn-icon" />
          <span v-if="running">Running...</span>
          <span v-else>Run All Operations</span>
        </button>
        <button @click="runTests" :disabled="running" class="action-btn">
          Run Tests Only
        </button>
        <button @click="runValidation" :disabled="running" class="action-btn">
          Run Validation Only
        </button>
        <button @click="runReports" :disabled="running" class="action-btn">
          Run Reports Only
        </button>
      </div>
    </div>

    <!-- Results Section -->
    <div v-if="results" class="results-section">
      <div class="section-header">
        <h2>Execution Results</h2>
        <div class="summary-badges">
          <span class="badge badge-success">
            ✅ {{ results.summary.successful }} Successful
          </span>
          <span class="badge badge-error">
            ❌ {{ results.summary.failed }} Failed
          </span>
          <span class="badge badge-info">
            📊 {{ results.summary.total }} Total
          </span>
        </div>
      </div>

      <div class="results-list">
        <div
          v-for="(result, index) in results.results"
          :key="index"
          class="result-item"
          :class="{ 'result-success': result.success, 'result-error': !result.success }"
        >
          <div class="result-header">
            <div class="result-icon">
              <CheckCircle2 v-if="result.success" />
              <XCircle v-else />
            </div>
            <div class="result-info">
              <h3>Operation {{ index + 1 }}: {{ result.operation.type }}</h3>
              <p v-if="result.operation.suite">Suite: {{ result.operation.suite }}</p>
              <p v-if="result.operation.policyFile">Policy File: {{ result.operation.policyFile }}</p>
            </div>
          </div>
          <div v-if="result.error" class="result-error-message">
            {{ result.error }}
          </div>
          <div v-if="result.data" class="result-data">
            <pre>{{ JSON.stringify(result.data, null, 2) }}</pre>
          </div>
        </div>
      </div>

      <div class="results-footer">
        <p>Output Directory: {{ results.outputDir }}</p>
      </div>
    </div>

    <!-- Upload Modal -->
    <Modal v-if="showUploadModal" @close="showUploadModal = false">
      <template #header>
        <h2>Upload Batch File</h2>
      </template>
      <template #body>
        <div class="upload-section">
          <input
            ref="fileInput"
            type="file"
            accept=".json,.yaml,.yml"
            @change="handleFileUpload"
            class="file-input"
          />
          <p class="upload-hint">Select a JSON or YAML batch file</p>
        </div>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Upload, Play, CheckCircle2, XCircle } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import Modal from '../components/Modal.vue';
import { useBatchOperations, type BatchFile, type BatchResult } from '../composables/useBatchOperations';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Batch Operations' },
];

const { runBatch, runBatchTest, runBatchValidate, runBatchReport, parseBatchFile, loading: running } = useBatchOperations();

const showUploadModal = ref(false);
const fileInput = ref<HTMLInputElement | null>(null);
const fileFormat = ref<'json' | 'yaml'>('json');
const batchFileContent = ref(`{
  "operations": [
    {
      "type": "test",
      "suite": "default",
      "output": "test-results-default"
    },
    {
      "type": "validate",
      "policyFile": "./policies/abac-policies.json",
      "output": "validation-results"
    }
  ],
  "config": {
    "outputDir": "./reports",
    "parallel": false,
    "stopOnError": true
  }
}`);

const results = ref<BatchResult | null>(null);

const loadExample = () => {
  batchFileContent.value = `{
  "operations": [
    {
      "type": "test",
      "suite": "default",
      "output": "test-results-default",
      "config": "./config/runtime-config.json"
    },
    {
      "type": "validate",
      "policyFile": "./policies/abac-policies.json",
      "output": "validation-results"
    },
    {
      "type": "report",
      "output": "final-report"
    }
  ],
  "config": {
    "outputDir": "./reports",
    "parallel": false,
    "stopOnError": true
  }
}`;
};

const validateFile = async () => {
  try {
    await parseBatchFile(batchFileContent.value, fileFormat.value);
    alert('Batch file is valid!');
  } catch (error: any) {
    alert(`Validation failed: ${error.message}`);
  }
};

const parseContent = async (): Promise<BatchFile> => {
  if (fileFormat.value === 'json') {
    return JSON.parse(batchFileContent.value);
  } else {
    // For YAML, we'd need a YAML parser on the frontend or use the API
    return await parseBatchFile(batchFileContent.value, 'yaml');
  }
};

const runAllOperations = async () => {
  try {
    const batchFile = await parseContent();
    results.value = await runBatch(batchFile);
  } catch (error: any) {
    alert(`Failed to run batch operations: ${error.message}`);
  }
};

const runTests = async () => {
  try {
    const batchFile = await parseContent();
    results.value = await runBatchTest(batchFile);
  } catch (error: any) {
    alert(`Failed to run batch tests: ${error.message}`);
  }
};

const runValidation = async () => {
  try {
    const batchFile = await parseContent();
    results.value = await runBatchValidate(batchFile);
  } catch (error: any) {
    alert(`Failed to run batch validation: ${error.message}`);
  }
};

const runReports = async () => {
  try {
    const batchFile = await parseContent();
    results.value = await runBatchReport(batchFile);
  } catch (error: any) {
    alert(`Failed to run batch reports: ${error.message}`);
  }
};

const handleFileUpload = async (event: Event) => {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target?.result as string;
    batchFileContent.value = content;
    
    // Detect format
    if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
      fileFormat.value = 'yaml';
    } else {
      fileFormat.value = 'json';
    }
    
    showUploadModal.value = false;
  };
  reader.readAsText(file);
};
</script>

<style scoped>
.batch-operations-page {
  padding: 2rem;
  max-width: 1800px;
  margin: 0 auto;
  width: 100%;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.batch-editor-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  margin-bottom: 2rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.section-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.section-actions {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.format-select {
  padding: 0.5rem;
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
}

.editor-container {
  margin-bottom: 1rem;
}

.batch-editor {
  width: 100%;
  min-height: 400px;
  padding: 1rem;
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  font-family: 'Courier New', monospace;
  font-size: 0.9rem;
  color: #a0aec0;
  resize: vertical;
}

.batch-editor::placeholder {
  color: #6b7280;
}

.editor-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
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

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.results-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.summary-badges {
  display: flex;
  gap: 0.5rem;
}

.badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 500;
}

.badge-success {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.badge-error {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.badge-info {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.results-list {
  margin-top: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.result-item {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
}

.result-item.result-success {
  border-color: rgba(34, 197, 94, 0.4);
  background: rgba(34, 197, 94, 0.05);
}

.result-item.result-error {
  border-color: rgba(239, 68, 68, 0.4);
  background: rgba(239, 68, 68, 0.05);
}

.result-header {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  margin-bottom: 0.5rem;
}

.result-icon {
  color: #22c55e;
  flex-shrink: 0;
}

.result-error .result-icon {
  color: #ef4444;
}

.result-info h3 {
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: 0.25rem;
  color: #ffffff;
}

.result-info p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0.25rem 0;
}

.result-error-message {
  margin-top: 0.5rem;
  padding: 0.75rem;
  background: rgba(239, 68, 68, 0.1);
  border-left: 3px solid #ef4444;
  color: #fc8181;
  font-size: 0.875rem;
  border-radius: 4px;
}

.result-data {
  margin-top: 0.5rem;
  padding: 0.75rem;
  background: rgba(26, 31, 46, 0.8);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 4px;
}

.result-data pre {
  margin: 0;
  font-size: 0.875rem;
  overflow-x: auto;
  color: #a0aec0;
}

.results-footer {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  color: #a0aec0;
  font-size: 0.875rem;
}

.upload-section {
  padding: 1rem;
}

.file-input {
  margin-bottom: 0.5rem;
  padding: 0.75rem;
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
}

.upload-hint {
  color: #a0aec0;
  font-size: 0.875rem;
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
</style>
