<template>
  <div class="policy-code-editor">
    <div class="editor-header">
      <h3>JSON Editor</h3>
      <div class="editor-actions">
        <button @click="formatJson" class="btn-secondary">Format</button>
        <button @click="validateJson" class="btn-secondary">Validate</button>
      </div>
    </div>
    <div class="editor-container">
      <textarea
        v-model="jsonContent"
        @input="onInput"
        class="json-editor"
        :class="{ 'has-errors': validationErrors.length > 0 }"
      ></textarea>
      <div v-if="validationErrors.length > 0" class="validation-errors">
        <div v-for="(error, index) in validationErrors" :key="index" class="error-item">
          <strong>{{ error.field }}:</strong> {{ error.message }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { usePolicyValidation } from '../../composables/usePolicyValidation';
import type { ValidationError } from '../../types/policy-builder';

const props = defineProps<{
  modelValue: string;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: string];
  'change': [value: string];
}>();

const { validate, errors } = usePolicyValidation();
const jsonContent = ref(props.modelValue);
const validationErrors = ref<ValidationError[]>([]);

watch(() => props.modelValue, (newValue) => {
  jsonContent.value = newValue;
});

const onInput = () => {
  emit('update:modelValue', jsonContent.value);
  emit('change', jsonContent.value);
};

const formatJson = () => {
  try {
    const parsed = JSON.parse(jsonContent.value);
    jsonContent.value = JSON.stringify(parsed, null, 2);
    emit('update:modelValue', jsonContent.value);
  } catch (error) {
    alert('Invalid JSON. Cannot format.');
  }
};

const validateJson = async () => {
  try {
    const result = await validate(jsonContent.value);
    validationErrors.value = result.errors;
    if (!result.valid) {
      console.error('Validation errors:', result.errors);
    }
  } catch (error) {
    console.error('Validation failed:', error);
  }
};

// Auto-validate on changes (debounced)
let validationTimeout: ReturnType<typeof setTimeout>;
watch(jsonContent, () => {
  clearTimeout(validationTimeout);
  validationTimeout = setTimeout(() => {
    validateJson();
  }, 500);
});
</script>

<style scoped>
.policy-code-editor {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.editor-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  border-bottom: 1px solid #e0e0e0;
}

.editor-actions {
  display: flex;
  gap: 0.5rem;
}

.editor-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  position: relative;
}

.json-editor {
  flex: 1;
  width: 100%;
  padding: 1rem;
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: 14px;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  resize: none;
  outline: none;
}

.json-editor.has-errors {
  border-color: #f56565;
}

.validation-errors {
  padding: 1rem;
  background: #fed7d7;
  border-top: 1px solid #f56565;
}

.error-item {
  margin-bottom: 0.5rem;
  color: #c53030;
}
</style>
