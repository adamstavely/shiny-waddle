<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content source-editor-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Code class="modal-title-icon" />
              <div>
                <h2>Edit Source File</h2>
                <p v-if="sourcePath" class="source-path-text">{{ sourcePath }}</p>
              </div>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body">
            <div v-if="loading" class="loading-state">
              <p>Loading source file...</p>
            </div>
            
            <div v-else-if="error" class="error-state">
              <AlertTriangle class="error-icon" />
              <p>{{ error }}</p>
            </div>
            
            <div v-else class="editor-container">
              <div class="editor-toolbar">
                <span class="file-type-badge" :class="sourceType">
                  {{ sourceType === 'typescript' ? 'TypeScript' : 'JSON' }}
                </span>
                <div class="toolbar-actions">
                  <button @click="formatCode" class="toolbar-btn" title="Format code">
                    <FileText class="icon" />
                    Format
                  </button>
                  <button @click="reload" class="toolbar-btn" title="Reload from file">
                    <RefreshCw class="icon" />
                    Reload
                  </button>
                </div>
              </div>
              
              <textarea
                v-model="content"
                class="source-editor"
                :class="sourceType"
                spellcheck="false"
                @input="onContentChange"
              ></textarea>
              
              <div v-if="hasChanges" class="unsaved-indicator">
                <AlertCircle class="icon" />
                <span>Unsaved changes</span>
              </div>
            </div>
          </div>
          
          <div class="modal-footer">
            <button @click="close" class="btn-secondary">
              Cancel
            </button>
            <button @click="save" class="btn-primary" :disabled="loading || !hasChanges">
              <Save class="icon" />
              Save Changes
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { Teleport } from 'vue';
import {
  Code,
  X,
  AlertTriangle,
  FileText,
  RefreshCw,
  AlertCircle,
  Save
} from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  show: boolean;
  suiteId: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  saved: [];
}>();

const loading = ref(false);
const error = ref<string | null>(null);
const content = ref('');
const originalContent = ref('');
const sourceType = ref<'typescript' | 'json'>('typescript');
const sourcePath = ref<string | undefined>();

const hasChanges = computed(() => {
  return content.value !== originalContent.value;
});

watch(() => props.show, async (show) => {
  if (show && props.suiteId) {
    await loadSource();
  } else {
    content.value = '';
    originalContent.value = '';
    error.value = null;
  }
}, { immediate: true });

const loadSource = async () => {
  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/test-suites/${props.suiteId}/source`);
    content.value = response.data.content;
    originalContent.value = response.data.content;
    sourceType.value = response.data.sourceType || 'typescript';
    sourcePath.value = response.data.sourcePath;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load source file';
    console.error('Error loading source:', err);
  } finally {
    loading.value = false;
  }
};

const reload = async () => {
  if (hasChanges.value && !confirm('You have unsaved changes. Reloading will discard them. Continue?')) {
    return;
  }
  await loadSource();
};

const formatCode = () => {
  try {
    if (sourceType.value === 'json') {
      const parsed = JSON.parse(content.value);
      content.value = JSON.stringify(parsed, null, 2);
    } else {
      // For TypeScript, we can't really format it properly without a parser
      // Just try to indent basic structures
      // This is a simplified formatter
      let formatted = content.value;
      let indent = 0;
      const lines = formatted.split('\n');
      formatted = lines.map(line => {
        const trimmed = line.trim();
        if (trimmed.endsWith('{') || trimmed.endsWith('[')) {
          const result = '  '.repeat(indent) + trimmed;
          indent++;
          return result;
        } else if (trimmed.startsWith('}') || trimmed.startsWith(']')) {
          indent = Math.max(0, indent - 1);
          return '  '.repeat(indent) + trimmed;
        } else {
          return '  '.repeat(indent) + trimmed;
        }
      }).join('\n');
      content.value = formatted;
    }
  } catch (err) {
    console.error('Error formatting code:', err);
    alert('Could not format code. Please check syntax.');
  }
};

const onContentChange = () => {
  // Content changed, hasChanges computed will update
};

const save = async () => {
  if (!hasChanges.value) {
    close();
    return;
  }

  loading.value = true;
  error.value = null;
  try {
    await axios.put(`/api/test-suites/${props.suiteId}/source`, {
      content: content.value,
    });
    originalContent.value = content.value;
    emit('saved');
    close();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to save source file';
    console.error('Error saving source:', err);
    alert(error.value);
  } finally {
    loading.value = false;
  }
};

const close = () => {
  if (hasChanges.value && !confirm('You have unsaved changes. Are you sure you want to close?')) {
    return;
  }
  emit('close');
};
</script>

<style scoped>
.source-editor-modal {
  max-width: 1000px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 4px;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.source-path-text {
  font-size: 0.875rem;
  color: #a0aec0;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  margin: 0;
}

.modal-body {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  padding: 0;
}

.loading-state,
.error-state {
  padding: 40px;
  text-align: center;
  color: #a0aec0;
}

.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  color: #f87171;
}

.error-icon {
  width: 32px;
  height: 32px;
}

.editor-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  padding: 16px;
}

.editor-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px 8px 0 0;
  margin-bottom: -1px;
}

.file-type-badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.file-type-badge.typescript {
  background: rgba(49, 120, 198, 0.2);
  color: #3178c6;
  border: 1px solid rgba(49, 120, 198, 0.3);
}

.file-type-badge.json {
  background: rgba(255, 193, 7, 0.2);
  color: #ffc107;
  border: 1px solid rgba(255, 193, 7, 0.3);
}

.toolbar-actions {
  display: flex;
  gap: 8px;
}

.toolbar-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.toolbar-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.toolbar-btn .icon {
  width: 14px;
  height: 14px;
}

.source-editor {
  flex: 1;
  width: 100%;
  min-height: 400px;
  padding: 16px;
  background: #1a1f2e;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 0 0 8px 8px;
  color: #e2e8f0;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  font-size: 14px;
  line-height: 1.6;
  resize: none;
  outline: none;
  tab-size: 2;
}

.source-editor:focus {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.unsaved-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
  padding: 8px 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 6px;
  color: #fbbf24;
  font-size: 0.875rem;
}

.unsaved-indicator .icon {
  width: 16px;
  height: 16px;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 20px 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-secondary,
.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-secondary {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.2);
}

.btn-secondary:hover {
  background: rgba(160, 174, 192, 0.2);
}

.btn-primary {
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
}

.btn-primary .icon {
  width: 16px;
  height: 16px;
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

