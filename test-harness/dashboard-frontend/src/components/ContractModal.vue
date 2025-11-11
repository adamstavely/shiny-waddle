<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <FileText class="modal-title-icon" />
              <h2>{{ contract ? 'Edit Contract' : 'Add Contract' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="save" class="contract-form">
              <div class="form-group">
                <label>Contract Name *</label>
                <input v-model="form.name" type="text" required />
              </div>
              <div class="form-group">
                <label>Data Owner *</label>
                <input v-model="form.dataOwner" type="text" required />
              </div>
              <div class="form-group">
                <label>Machine Readable</label>
                <div class="checkbox-group">
                  <label class="checkbox-label">
                    <input v-model="form.machineReadable" type="checkbox" />
                    This contract is machine-readable
                  </label>
                </div>
              </div>

              <div class="section-divider">
                <h3>Contract Requirements</h3>
                <button type="button" @click="addRequirement" class="btn-small">
                  <Plus class="btn-icon-small" />
                  Add Requirement
                </button>
              </div>

              <div
                v-for="(req, index) in form.requirements"
                :key="index"
                class="requirement-item"
              >
                <div class="requirement-header">
                  <h4>Requirement {{ index + 1 }}</h4>
                  <button type="button" @click="removeRequirement(index)" class="btn-icon-only">
                    <X class="icon" />
                  </button>
                </div>
                <div class="form-group">
                  <label>Description *</label>
                  <input v-model="req.description" type="text" required />
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Type *</label>
                    <select v-model="req.type" required>
                      <option value="field-restriction">Field Restriction</option>
                      <option value="aggregation-requirement">Aggregation Requirement</option>
                      <option value="join-restriction">Join Restriction</option>
                      <option value="export-restriction">Export Restriction</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Enforcement *</label>
                    <select v-model="req.enforcement" required>
                      <option value="hard">Hard</option>
                      <option value="soft">Soft</option>
                    </select>
                  </div>
                </div>
                <div class="form-group">
                  <label>Rule Configuration (JSON)</label>
                  <textarea v-model="ruleInputs[index]" rows="4" class="code-input"></textarea>
                  <small>Enter rule configuration as JSON</small>
                </div>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary">Save Contract</button>
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
import { FileText, X, Plus } from 'lucide-vue-next';

interface Props {
  show: boolean;
  contract?: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [data: any];
}>();

const form = ref({
  name: '',
  dataOwner: '',
  machineReadable: false,
  requirements: [] as any[]
});

const ruleInputs = ref<string[]>([]);

watch(() => props.contract, (contract) => {
  if (contract) {
    form.value = {
      name: contract.name || '',
      dataOwner: contract.dataOwner || '',
      machineReadable: contract.machineReadable || false,
      requirements: contract.requirements ? [...contract.requirements] : []
    };
    ruleInputs.value = contract.requirements
      ? contract.requirements.map((r: any) => JSON.stringify(r.rule, null, 2))
      : [];
  } else {
    resetForm();
  }
}, { immediate: true });

watch(() => props.show, (show) => {
  if (!show) {
    resetForm();
  }
});

watch(() => form.value.requirements.length, (newLength, oldLength) => {
  if (newLength > oldLength) {
    ruleInputs.value.push('{}');
  } else if (newLength < oldLength) {
    ruleInputs.value.pop();
  }
});

function resetForm() {
  form.value = {
    name: '',
    dataOwner: '',
    machineReadable: false,
    requirements: []
  };
  ruleInputs.value = [];
}

function addRequirement() {
  form.value.requirements.push({
    id: `req-${Date.now()}`,
    description: '',
    type: 'field-restriction',
    rule: {},
    enforcement: 'hard'
  });
  ruleInputs.value.push('{}');
}

function removeRequirement(index: number) {
  form.value.requirements.splice(index, 1);
  ruleInputs.value.splice(index, 1);
}

function close() {
  emit('close');
}

function save() {
  // Parse rule JSON strings
  const contractData = {
    ...form.value,
    requirements: form.value.requirements.map((req, index) => ({
      ...req,
      rule: parseRule(ruleInputs.value[index] || '{}')
    }))
  };
  emit('save', contractData);
}

function parseRule(ruleStr: string): any {
  try {
    return JSON.parse(ruleStr);
  } catch {
    return {};
  }
}
</script>

<style scoped>
.large-modal {
  max-width: 800px;
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
  position: sticky;
  top: 0;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  z-index: 10;
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

.contract-form {
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

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #a0aec0;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.section-divider {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 24px 0 16px 0;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.section-divider h3 {
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-small {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon-small {
  width: 14px;
  height: 14px;
}

.requirement-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  margin-bottom: 12px;
}

.requirement-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.requirement-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-icon-only {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 8px;
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 6px;
  color: #fc8181;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-icon-only:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.btn-icon-only .icon {
  width: 16px;
  height: 16px;
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

