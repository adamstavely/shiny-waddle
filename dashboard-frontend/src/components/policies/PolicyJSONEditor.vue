<template>
  <div class="policy-json-editor">
    <div class="editor-toolbar">
      <div class="toolbar-actions">
        <button @click="formatJSON" class="btn-toolbar" type="button">
          Format
        </button>
        <button @click="validateJSON" class="btn-toolbar" type="button">
          Validate
        </button>
        <button @click="copyJSON" class="btn-toolbar" type="button">
          Copy
        </button>
      </div>
      <div v-if="validationError" class="validation-error">
        <AlertTriangle class="error-icon" />
        {{ validationError }}
      </div>
      <div v-else-if="isValid" class="validation-success">
        <CheckCircle2 class="success-icon" />
        Valid JSON
      </div>
    </div>
    <div ref="editorContainer" class="editor-container"></div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch } from 'vue';
import { AlertTriangle, CheckCircle2 } from 'lucide-vue-next';
import loader from '@monaco-editor/loader';

const props = defineProps<{
  modelValue: string;
  language?: string;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: string];
}>();

const editorContainer = ref<HTMLElement | null>(null);
let editor: any = null;
const validationError = ref<string>('');
const isValid = ref(false);

onMounted(async () => {
  if (!editorContainer.value) return;

  try {
    // Load Monaco Editor
    const monaco = await loader.init();
    
    // Create Monaco Editor instance
    editor = monaco.editor.create(editorContainer.value, {
      value: props.modelValue || '{}',
      language: props.language || 'json',
      theme: 'vs-dark',
      automaticLayout: true,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      formatOnPaste: true,
      formatOnType: true,
      tabSize: 2,
      wordWrap: 'on',
    });

    // Listen for changes
    editor.onDidChangeModelContent(() => {
      const value = editor?.getValue() || '';
      emit('update:modelValue', value);
      validateJSONContent(value);
    });

    // Initial validation
    validateJSONContent(props.modelValue || '{}');
  } catch (error) {
    console.error('Error loading Monaco Editor:', error);
    validationError.value = 'Failed to load editor';
  }
});

onBeforeUnmount(() => {
  if (editor) {
    editor.dispose();
  }
});

watch(() => props.modelValue, (newValue) => {
  if (editor && editor.getValue() !== newValue) {
    editor.setValue(newValue || '{}');
    validateJSONContent(newValue || '{}');
  }
});

const validateJSONContent = (content: string) => {
  validationError.value = '';
  isValid.value = false;

  if (!content.trim()) {
    return;
  }

  try {
    JSON.parse(content);
    isValid.value = true;
  } catch (error: any) {
    validationError.value = error.message || 'Invalid JSON';
    isValid.value = false;
  }
};

const formatJSON = () => {
  if (!editor) return;

  try {
    const content = editor.getValue();
    const parsed = JSON.parse(content);
    const formatted = JSON.stringify(parsed, null, 2);
    editor.setValue(formatted);
    isValid.value = true;
    validationError.value = '';
  } catch (error: any) {
    validationError.value = error.message || 'Cannot format invalid JSON';
    isValid.value = false;
  }
};

const validateJSON = () => {
  if (!editor) return;
  validateJSONContent(editor.getValue());
};

const copyJSON = () => {
  if (!editor) return;
  navigator.clipboard.writeText(editor.getValue());
  alert('JSON copied to clipboard');
};
</script>

<style scoped>
.policy-json-editor {
  display: flex;
  flex-direction: column;
  height: 100%;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  overflow: hidden;
}

.editor-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-secondary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.toolbar-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.btn-toolbar {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-xs);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-toolbar:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.validation-error,
.validation-success {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  font-size: var(--font-size-xs);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
}

.validation-error {
  color: var(--color-error);
  background: var(--color-error-bg);
}

.validation-success {
  color: var(--color-success);
  background: var(--color-success-bg);
}

.error-icon,
.success-icon {
  width: 14px;
  height: 14px;
}

.editor-container {
  flex: 1;
  min-height: 400px;
}
</style>
