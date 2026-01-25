<template>
  <div class="policy-rule-builder">
    <div class="builder-header">
      <h3>{{ policyType === 'rbac' ? 'Policy Rules' : 'Policy Conditions' }}</h3>
      <button @click="addRule" class="btn-add-rule">
        <Plus class="btn-icon" />
        Add {{ policyType === 'rbac' ? 'Rule' : 'Condition' }}
      </button>
    </div>

    <!-- Drag and Drop Container -->
    <div class="rules-container">
      <VueDraggableNext
        v-model="rules"
        :animation="200"
        handle=".drag-handle"
        :item-key="policyType === 'rbac' ? 'id' : (item: any, index: number) => index"
        class="rules-list"
      >
        <template #item="{ element: rule, index }">
          <div class="rule-card" :class="{ 'dragging': false }">
            <div class="rule-header">
              <div class="drag-handle">
                <GripVertical class="drag-icon" />
              </div>
              <h4>{{ policyType === 'rbac' ? `Rule ${index + 1}` : `Condition ${index + 1}` }}</h4>
              <button @click="removeRule(index)" class="btn-remove" type="button">
                <Trash2 class="icon" />
              </button>
            </div>

            <!-- RBAC Rule Builder -->
            <div v-if="policyType === 'rbac'" class="rule-content">
              <div class="form-group">
                <label>Rule ID</label>
                <input
                  v-model="rule.id"
                  type="text"
                  placeholder="e.g., admin-full-access"
                  required
                />
              </div>
              <div class="form-group">
                <label>Description</label>
                <textarea
                  v-model="rule.description"
                  rows="2"
                  placeholder="Describe what this rule does"
                ></textarea>
              </div>
              <div class="form-group">
                <label>Effect</label>
                <Dropdown
                  v-model="rule.effect"
                  :options="effectOptions"
                  placeholder="Select effect..."
                />
              </div>
              <div class="form-group">
                <label>Conditions</label>
                <div class="conditions-builder">
                  <VueDraggableNext
                    v-model="rule.conditions"
                    :animation="150"
                    handle=".condition-drag-handle"
                    item-key="key"
                    class="conditions-list"
                  >
                    <template #item="{ element: condition }">
                      <div class="condition-row">
                        <div class="condition-drag-handle">
                          <GripVertical class="drag-icon small" />
                        </div>
                        <input
                          v-model="condition.key"
                          type="text"
                          placeholder="e.g., subject.role"
                          class="condition-key"
                        />
                        <span class="condition-separator">:</span>
                        <input
                          v-model="condition.value"
                          type="text"
                          placeholder="e.g., admin or [admin, viewer]"
                          class="condition-value"
                        />
                        <button
                          @click="removeCondition(rule, condition)"
                          class="btn-remove-small"
                          type="button"
                        >
                          <X class="icon" />
                        </button>
                      </div>
                    </template>
                  </VueDraggableNext>
                  <button @click="addCondition(rule)" class="btn-add-condition" type="button">
                    <Plus class="icon" />
                    Add Condition
                  </button>
                </div>
              </div>
            </div>

            <!-- ABAC Condition Builder -->
            <div v-else class="rule-content">
              <div class="form-group">
                <label>Attribute</label>
                <Dropdown
                  v-model="rule.attribute"
                  :options="attributeOptions"
                  placeholder="Select attribute..."
                />
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Operator</label>
                  <Dropdown
                    v-model="rule.operator"
                    :options="operatorOptions"
                    placeholder="Select operator..."
                  />
                </div>
                <div class="form-group">
                  <label>Logical Operator</label>
                  <Dropdown
                    v-model="rule.logicalOperator"
                    :options="logicalOperatorOptions"
                    placeholder="None (First Condition)"
                  />
                  <small>How to combine with previous condition</small>
                </div>
              </div>
              <div class="form-group">
                <label>Value</label>
                <input
                  v-model="rule.value"
                  type="text"
                  placeholder="e.g., admin or [admin, viewer] or {{resource.department}}"
                  required
                />
                <small>Use {{resource.attribute}} or {{subject.attribute}} for dynamic values</small>
              </div>
            </div>
          </div>
        </template>
      </VueDraggableNext>
    </div>

    <div v-if="rules.length === 0" class="empty-state">
      <p>No {{ policyType === 'rbac' ? 'rules' : 'conditions' }} yet. Click "Add" to create one.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { VueDraggableNext } from 'vue-draggable-next';
import { Plus, Trash2, X, GripVertical } from 'lucide-vue-next';
import Dropdown from '../Dropdown.vue';

interface RBACRule {
  id: string;
  description?: string;
  effect: 'allow' | 'deny';
  conditions: Array<{ key: string; value: string }>;
}

interface ABACCondition {
  attribute: string;
  operator: string;
  value: string;
  logicalOperator?: 'AND' | 'OR';
}

const props = defineProps<{
  policyType: 'rbac' | 'abac';
  modelValue: RBACRule[] | ABACCondition[];
}>();

const emit = defineEmits<{
  'update:modelValue': [value: RBACRule[] | ABACCondition[]];
}>();

const rules = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
});

const effectOptions = [
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' },
];

const attributeOptions = [
  { label: 'Subject Department', value: 'subject.department' },
  { label: 'Subject Role', value: 'subject.role' },
  { label: 'Subject Clearance Level', value: 'subject.clearanceLevel' },
  { label: 'Subject Project Access', value: 'subject.projectAccess' },
  { label: 'Resource Department', value: 'resource.department' },
  { label: 'Resource Data Classification', value: 'resource.dataClassification' },
  { label: 'Resource Project', value: 'resource.project' },
  { label: 'Context IP Address', value: 'context.ipAddress' },
  { label: 'Context Time', value: 'context.time' },
];

const operatorOptions = [
  { label: 'Equals', value: 'equals' },
  { label: 'Not Equals', value: 'notEquals' },
  { label: 'In', value: 'in' },
  { label: 'Not In', value: 'notIn' },
  { label: 'Greater Than', value: 'greaterThan' },
  { label: 'Less Than', value: 'lessThan' },
  { label: 'Contains', value: 'contains' },
  { label: 'Starts With', value: 'startsWith' },
  { label: 'Ends With', value: 'endsWith' },
  { label: 'Regex', value: 'regex' },
];

const logicalOperatorOptions = [
  { label: 'None (First Condition)', value: '' },
  { label: 'AND', value: 'AND' },
  { label: 'OR', value: 'OR' },
];

const addRule = () => {
  if (props.policyType === 'rbac') {
    const newRule: RBACRule = {
      id: `rule-${Date.now()}`,
      description: '',
      effect: 'allow',
      conditions: [],
    };
    rules.value = [...rules.value, newRule] as RBACRule[];
  } else {
    const newCondition: ABACCondition = {
      attribute: '',
      operator: 'equals',
      value: '',
      logicalOperator: undefined,
    };
    rules.value = [...rules.value, newCondition] as ABACCondition[];
  }
};

const removeRule = (index: number) => {
  const newRules = [...rules.value];
  newRules.splice(index, 1);
  rules.value = newRules;
};

const addCondition = (rule: RBACRule) => {
  if (props.policyType === 'rbac') {
    rule.conditions.push({ key: '', value: '' });
  }
};

const removeCondition = (rule: RBACRule, condition: { key: string; value: string }) => {
  if (props.policyType === 'rbac') {
    const index = rule.conditions.indexOf(condition);
    if (index > -1) {
      rule.conditions.splice(index, 1);
    }
  }
};
</script>

<style scoped>
.policy-rule-builder {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.builder-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.builder-header h3 {
  margin: 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--color-text-primary);
}

.btn-add-rule {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--gradient-primary, linear-gradient(135deg, #667eea 0%, #764ba2 100%));
  color: white;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-add-rule:hover {
  opacity: 0.9;
}

.rules-container {
  min-height: 200px;
}

.rules-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.rule-card {
  background: var(--color-bg-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  transition: var(--transition-all);
}

.rule-card:hover {
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-sm);
}

.rule-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.drag-handle {
  cursor: grab;
  color: var(--color-text-muted);
  display: flex;
  align-items: center;
}

.drag-handle:active {
  cursor: grabbing;
}

.drag-icon {
  width: 18px;
  height: 18px;
}

.drag-icon.small {
  width: 14px;
  height: 14px;
}

.rule-header h4 {
  flex: 1;
  margin: 0;
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.btn-remove {
  background: none;
  border: none;
  color: var(--color-error);
  cursor: pointer;
  padding: var(--spacing-xs);
  display: flex;
  align-items: center;
  transition: var(--transition-all);
}

.btn-remove:hover {
  opacity: 0.7;
}

.rule-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-info-bg);
}

.form-group small {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.conditions-builder {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.conditions-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.condition-row {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
}

.condition-drag-handle {
  cursor: grab;
  color: var(--color-text-muted);
  display: flex;
  align-items: center;
}

.condition-drag-handle:active {
  cursor: grabbing;
}

.condition-key {
  flex: 1;
  padding: var(--spacing-xs);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.condition-separator {
  color: var(--color-text-muted);
  font-weight: var(--font-weight-semibold);
}

.condition-value {
  flex: 1;
  padding: var(--spacing-xs);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.btn-remove-small {
  background: none;
  border: none;
  color: var(--color-error);
  cursor: pointer;
  padding: var(--spacing-xs);
  display: flex;
  align-items: center;
  transition: var(--transition-all);
}

.btn-remove-small:hover {
  opacity: 0.7;
}

.btn-add-condition {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) dashed var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-muted);
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.btn-add-condition:hover {
  background: var(--color-bg-overlay);
  border-color: var(--border-color-primary-hover);
  color: var(--color-text-primary);
}

.empty-state {
  padding: var(--spacing-xl);
  text-align: center;
  color: var(--color-text-muted);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) dashed var(--border-color-primary);
}

.icon {
  width: 16px;
  height: 16px;
}
</style>
