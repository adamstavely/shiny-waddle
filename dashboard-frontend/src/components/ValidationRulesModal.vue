<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content large" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <FileText class="modal-title-icon" />
              <h2>Validation Rules - {{ target?.name }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="rules-header">
              <button @click="showAddRuleModal = true" class="btn-primary">
                <Plus class="btn-icon" />
                Add Rule
              </button>
            </div>

            <div class="rules-list">
              <div
                v-for="rule in rules"
                :key="rule.id"
                class="rule-card"
              >
                <div class="rule-header">
                  <div>
                    <h4 class="rule-name">{{ rule.name }}</h4>
                    <p class="rule-description">{{ rule.description }}</p>
                  </div>
                  <div class="rule-badges">
                    <span class="severity-badge" :class="`severity-${rule.severity}`">
                      {{ rule.severity }}
                    </span>
                    <label class="toggle-label">
                      <input
                        type="checkbox"
                        :checked="rule.enabled"
                        @change="toggleRule(rule)"
                        class="toggle-input"
                      />
                      <span class="toggle-slider"></span>
                    </label>
                  </div>
                </div>
                <div class="rule-actions">
                  <button @click="editRule(rule)" class="action-btn edit-btn">
                    <Edit class="action-icon" />
                    Edit
                  </button>
                  <button @click="deleteRule(rule)" class="action-btn delete-btn">
                    <Trash2 class="action-icon" />
                    Delete
                  </button>
                </div>
              </div>
            </div>

            <div v-if="rules.length === 0" class="empty-rules">
              <FileText class="empty-icon" />
              <p>No validation rules configured</p>
              <button @click="showAddRuleModal = true" class="btn-primary">
                Add First Rule
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>

  <!-- Add/Edit Rule Modal -->
  <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddRuleModal" class="modal-overlay" @click="showAddRuleModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <FileText class="modal-title-icon" />
                <h2>{{ editingRule ? 'Edit Rule' : 'Add Rule' }}</h2>
              </div>
              <button @click="showAddRuleModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="handleRuleSubmit" class="rule-form">
                <div class="form-group">
                  <label>Rule Name *</label>
                  <input v-model="ruleForm.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Description *</label>
                  <textarea v-model="ruleForm.description" rows="3" required></textarea>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Severity *</label>
                    <Dropdown
                      v-model="ruleForm.severity"
                      :options="severityOptions"
                      placeholder="Select severity..."
                    />
                  </div>
                  <div class="form-group">
                    <label>Check Type</label>
                    <input v-model="ruleForm.checkType" type="text" placeholder="e.g., security-settings" />
                  </div>
                </div>
                <div class="form-group">
                  <label>Rule Configuration (JSON) *</label>
                  <textarea
                    v-model="ruleForm.configJson"
                    rows="6"
                    required
                    class="json-input"
                    placeholder='{"check": "value", "expected": "something"}'
                  ></textarea>
                </div>
                <div class="form-actions">
                  <button type="button" @click="showAddRuleModal = false" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    {{ editingRule ? 'Update' : 'Add' }} Rule
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
import { FileText, X, Plus, Edit, Trash2 } from 'lucide-vue-next';
import { Teleport } from 'vue';
import axios from 'axios';
import Dropdown from './Dropdown.vue';

const props = defineProps<{
  show: boolean;
  target: any | null;
  rules: any[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [];
}>();

const showAddRuleModal = ref(false);
const editingRule = ref<any>(null);

const ruleForm = ref({
  name: '',
  description: '',
  severity: 'medium',
  checkType: '',
  configJson: '{}',
});

const severityOptions = [
  { label: 'Low', value: 'low' },
  { label: 'Medium', value: 'medium' },
  { label: 'High', value: 'high' },
  { label: 'Critical', value: 'critical' },
];

const toggleRule = async (rule: any) => {
  try {
    await axios.patch(`/api/validation-rules/${rule.id}`, {
      enabled: !rule.enabled,
    });
    emit('submit');
  } catch (err) {
    console.error('Error toggling rule:', err);
  }
};

const editRule = (rule: any) => {
  editingRule.value = rule;
  ruleForm.value = {
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    checkType: rule.checkType || '',
    configJson: rule.ruleConfig ? JSON.stringify(rule.ruleConfig, null, 2) : '{}',
  };
  showAddRuleModal.value = true;
};

const deleteRule = async (rule: any) => {
  if (!confirm(`Are you sure you want to delete rule "${rule.name}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/validation-rules/${rule.id}`);
    emit('submit');
  } catch (err) {
    console.error('Error deleting rule:', err);
  }
};

const handleRuleSubmit = async () => {
  if (!props.target) return;

  try {
    let config = {};
    try {
      config = JSON.parse(ruleForm.value.configJson);
    } catch (e) {
      alert('Invalid JSON in configuration field');
      return;
    }

    const payload = {
      name: ruleForm.value.name,
      description: ruleForm.value.description,
      severity: ruleForm.value.severity,
      ruleConfig: config,
      checkType: ruleForm.value.checkType || undefined,
    };

    if (editingRule.value) {
      await axios.patch(`/api/validation-rules/${editingRule.value.id}`, payload);
    } else {
      await axios.post(`/api/validation-targets/${props.target.id}/rules`, payload);
    }

    showAddRuleModal.value = false;
    editingRule.value = null;
    ruleForm.value = {
      name: '',
      description: '',
      severity: 'medium',
      checkType: '',
      configJson: '{}',
    };
    emit('submit');
  } catch (err) {
    console.error('Error saving rule:', err);
    alert('Failed to save rule');
  }
};

watch(() => props.show, (val) => {
  if (!val) {
    showAddRuleModal.value = false;
    editingRule.value = null;
  }
});
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
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-content.large {
  max-width: 1000px;
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

.rules-header {
  margin-bottom: 20px;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
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

.btn-icon {
  width: 18px;
  height: 18px;
}

.rules-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.rule-card {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.rule-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}

.rule-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.rule-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin: 0;
}

.rule-badges {
  display: flex;
  align-items: center;
  gap: 12px;
}

.severity-badge {
  padding: 4px 12px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.severity-low {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.severity-medium {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.severity-high {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.severity-critical {
  background: rgba(220, 38, 38, 0.2);
  color: #dc2626;
}

.toggle-label {
  display: flex;
  align-items: center;
  cursor: pointer;
}

.toggle-input {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: relative;
  width: 44px;
  height: 24px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  transition: all 0.2s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 18px;
  height: 18px;
  left: 3px;
  top: 3px;
  background: #718096;
  border-radius: 50%;
  transition: all 0.2s;
}

.toggle-input:checked + .toggle-slider {
  background: rgba(79, 172, 254, 0.4);
}

.toggle-input:checked + .toggle-slider::before {
  transform: translateX(20px);
  background: #4facfe;
}

.rule-actions {
  display: flex;
  gap: 8px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.edit-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-rules {
  text-align: center;
  padding: 60px 40px;
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.empty-rules p {
  color: #a0aec0;
  margin-bottom: 16px;
}

.rule-form {
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
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.json-input {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

