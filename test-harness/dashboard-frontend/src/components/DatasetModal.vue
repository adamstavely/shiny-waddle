<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Database class="modal-title-icon" />
              <h2>{{ dataset ? 'Edit Dataset' : 'Add Dataset' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="save" class="dataset-form">
              <div class="form-group">
                <label>Dataset Name *</label>
                <input v-model="form.name" type="text" required />
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Type *</label>
                  <select v-model="form.type" required>
                    <option value="raw">Raw</option>
                    <option value="masked">Masked</option>
                    <option value="synthetic">Synthetic</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>Record Count</label>
                  <input v-model.number="form.recordCount" type="number" min="0" />
                </div>
              </div>

              <div class="form-group">
                <label>PII Fields</label>
                <div class="tags-input">
                  <span
                    v-for="(field, index) in piiFieldsList"
                    :key="index"
                    class="tag"
                  >
                    {{ field }}
                    <button type="button" @click="removePiiField(index)" class="tag-remove">
                      <X class="tag-icon" />
                    </button>
                  </span>
                  <input
                    v-model="newPiiField"
                    type="text"
                    placeholder="Add PII field and press Enter"
                    @keydown.enter.prevent="addPiiField"
                    class="tag-input"
                  />
                </div>
              </div>

              <div class="form-group">
                <label>Schema (JSON)</label>
                <textarea v-model="schemaInput" rows="6" class="code-input"></textarea>
                <small>Enter dataset schema as JSON</small>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary">Save Dataset</button>
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
import { Teleport } from 'vue';
import { Database, X } from 'lucide-vue-next';

interface Props {
  show: boolean;
  dataset?: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [data: any];
}>();

const form = ref({
  name: '',
  type: 'raw',
  recordCount: 0,
  piiFields: [] as string[]
});

const newPiiField = ref('');
const schemaInput = ref('{}');

const piiFieldsList = computed({
  get: () => form.value.piiFields || [],
  set: (val) => {
    form.value.piiFields = val;
  }
});

watch(() => props.dataset, (dataset) => {
  if (dataset) {
    form.value = {
      name: dataset.name || '',
      type: dataset.type || 'raw',
      recordCount: dataset.recordCount || 0,
      piiFields: dataset.piiFields || []
    };
    schemaInput.value = JSON.stringify(dataset.schema || {}, null, 2);
  } else {
    resetForm();
  }
}, { immediate: true });

watch(() => props.show, (show) => {
  if (!show) {
    resetForm();
  }
});

function resetForm() {
  form.value = {
    name: '',
    type: 'raw',
    recordCount: 0,
    piiFields: []
  };
  newPiiField.value = '';
  schemaInput.value = '{}';
}

function addPiiField() {
  if (newPiiField.value.trim() && !piiFieldsList.value.includes(newPiiField.value.trim())) {
    piiFieldsList.value.push(newPiiField.value.trim());
    newPiiField.value = '';
  }
}

function removePiiField(index: number) {
  piiFieldsList.value.splice(index, 1);
}

function close() {
  emit('close');
}

function save() {
  let schema = {};
  try {
    schema = JSON.parse(schemaInput.value);
  } catch {
    schema = {};
  }
  emit('save', {
    ...form.value,
    schema
  });
}
</script>

<style scoped>
.large-modal {
  max-width: 700px;
}

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
  max-width: 600px;
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
  flex-shrink: 0;
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

.dataset-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group select,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.tags-input {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  min-height: 48px;
}

.tag {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: rgba(251, 191, 36, 0.2);
  border-radius: 6px;
  color: #fbbf24;
  font-size: 0.875rem;
}

.tag-remove {
  display: flex;
  align-items: center;
  padding: 2px;
  background: transparent;
  border: none;
  cursor: pointer;
  color: #fbbf24;
  transition: color 0.2s;
}

.tag-remove:hover {
  color: #fc8181;
}

.tag-icon {
  width: 12px;
  height: 12px;
}

.tag-input {
  flex: 1;
  min-width: 150px;
  background: transparent;
  border: none;
  color: #ffffff;
  font-size: 0.9rem;
  outline: none;
}

.code-input {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-primary {
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
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

