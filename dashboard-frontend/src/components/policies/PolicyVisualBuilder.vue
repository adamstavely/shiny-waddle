<template>
  <div class="policy-visual-builder">
    <div class="builder-toolbar">
      <div class="toolbar-section">
        <h4>Templates</h4>
        <div class="template-selector">
          <Dropdown
            v-model="selectedTemplateId"
            :options="templateOptions"
            placeholder="Select a template..."
            @update:model-value="applyTemplate"
          />
          <button
            v-if="selectedTemplateId"
            @click="clearTemplate"
            class="btn-clear-template"
            type="button"
          >
            Clear
          </button>
        </div>
      </div>
      <div class="toolbar-section">
        <h4>Elements</h4>
        <div class="element-palette">
          <!-- RBAC Elements -->
          <template v-if="policyType === 'rbac'">
            <div class="palette-item" draggable="true" @dragstart="handleDragStart($event, 'rule')">
              <Shield class="palette-icon" />
              <span>Rule</span>
            </div>
            <div class="palette-item" draggable="true" @dragstart="handleDragStart($event, 'condition')">
              <Filter class="palette-icon" />
              <span>Condition</span>
            </div>
          </template>
          <!-- ABAC Elements -->
          <template v-else>
            <div class="palette-item" draggable="true" @dragstart="handleDragStart($event, 'condition')">
              <Filter class="palette-icon" />
              <span>Condition</span>
            </div>
            <div class="palette-item" draggable="true" @dragstart="handleDragStart($event, 'logical')">
              <GitBranch class="palette-icon" />
              <span>Logical Operator</span>
            </div>
          </template>
        </div>
      </div>
    </div>

    <div class="builder-workspace">
      <div class="workspace-header">
        <h4>Policy Structure</h4>
        <div class="workspace-actions">
          <button @click="clearAll" class="btn-secondary small" type="button">
            Clear All
          </button>
          <button @click="importFromJSON" class="btn-secondary small" type="button">
            Import JSON
          </button>
        </div>
      </div>

      <!-- Visual Builder Area -->
      <div
        class="workspace-area"
        @drop="handleDrop"
        @dragover.prevent
        @dragenter.prevent
      >
        <!-- Use PolicyRuleBuilder for the actual rule building -->
        <PolicyRuleBuilder
          :policy-type="policyType"
          :model-value="rules"
          @update:model-value="handleRulesUpdate"
        />
      </div>
    </div>

    <!-- JSON Preview Panel -->
    <div class="preview-panel">
      <div class="panel-header">
        <h4>JSON Preview</h4>
        <button @click="copyJSON" class="btn-secondary small" type="button">
          Copy JSON
        </button>
      </div>
      <pre class="json-preview">{{ formattedJSON }}</pre>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { Shield, Filter, GitBranch } from 'lucide-vue-next';
import PolicyRuleBuilder from './PolicyRuleBuilder.vue';
import Dropdown from '../Dropdown.vue';
import axios from 'axios';

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

// Template management
const templates = ref<any[]>([]);
const selectedTemplateId = ref<string>('');
const loadingTemplates = ref(false);

const templateOptions = computed(() => {
  return templates.value
    .filter(t => t.type === props.policyType)
    .map(t => ({
      label: t.name,
      value: t.id,
    }));
});

const loadTemplates = async () => {
  try {
    loadingTemplates.value = true;
    const response = await axios.get('/api/policies/templates', {
      params: { type: props.policyType },
    });
    templates.value = response.data;
  } catch (error) {
    console.error('Error loading templates:', error);
  } finally {
    loadingTemplates.value = false;
  }
};

const applyTemplate = async (templateId: string) => {
  if (!templateId) return;
  
  try {
    const template = templates.value.find(t => t.id === templateId);
    if (!template) return;

    // Increment usage count
    await axios.post(`/api/policies/templates/${templateId}/use`);

    // Apply template to rules
    if (props.policyType === 'rbac' && template.template.rules) {
      const importedRules: RBACRule[] = template.template.rules.map((rule: any) => ({
        id: rule.id || `rule-${Date.now()}`,
        description: rule.description || '',
        effect: rule.effect || 'allow',
        conditions: Object.entries(rule.conditions || {}).map(([key, value]) => ({
          key,
          value: Array.isArray(value) ? JSON.stringify(value) : String(value),
        })),
      }));
      rules.value = importedRules as RBACRule[];
    } else if (props.policyType === 'abac' && template.template.conditions) {
      rules.value = template.template.conditions as ABACCondition[];
    }
  } catch (error) {
    console.error('Error applying template:', error);
    alert('Failed to apply template');
  }
};

const clearTemplate = () => {
  selectedTemplateId.value = '';
};

const handleRulesUpdate = (newRules: RBACRule[] | ABACCondition[]) => {
  rules.value = newRules;
};

const formattedJSON = computed(() => {
  if (props.policyType === 'rbac') {
    return JSON.stringify(
      {
        rules: rules.value.map((rule: any) => ({
          id: rule.id,
          description: rule.description,
          effect: rule.effect,
          conditions: rule.conditions.reduce((acc: any, cond: any) => {
            if (cond.key && cond.value) {
              acc[cond.key] = cond.value;
            }
            return acc;
          }, {}),
        })),
      },
      null,
      2
    );
  } else {
    return JSON.stringify(
      {
        conditions: rules.value,
      },
      null,
      2
    );
  }
});

const handleDragStart = (event: DragEvent, type: string) => {
  if (event.dataTransfer) {
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('application/json', JSON.stringify({ type }));
  }
};

const handleDrop = (event: DragEvent) => {
  event.preventDefault();
  try {
    const data = JSON.parse(event.dataTransfer?.getData('application/json') || '{}');
    if (data.type === 'rule' && props.policyType === 'rbac') {
      const newRule: RBACRule = {
        id: `rule-${Date.now()}`,
        description: '',
        effect: 'allow',
        conditions: [],
      };
      rules.value = [...rules.value, newRule] as RBACRule[];
    } else if (data.type === 'condition') {
      if (props.policyType === 'rbac') {
        // Add condition to last rule or create new rule
        if (rules.value.length === 0) {
          const newRule: RBACRule = {
            id: `rule-${Date.now()}`,
            description: '',
            effect: 'allow',
            conditions: [{ key: '', value: '' }],
          };
          rules.value = [newRule] as RBACRule[];
        } else {
          const lastRule = rules.value[rules.value.length - 1] as RBACRule;
          if (lastRule.conditions) {
            lastRule.conditions.push({ key: '', value: '' });
          }
        }
      } else {
        const newCondition: ABACCondition = {
          attribute: '',
          operator: 'equals',
          value: '',
        };
        rules.value = [...rules.value, newCondition] as ABACCondition[];
      }
    }
  } catch (error) {
    console.error('Error handling drop:', error);
  }
};

const clearAll = () => {
  rules.value = [];
};

const importFromJSON = () => {
  const jsonStr = prompt('Paste policy JSON:');
  if (!jsonStr) return;

  try {
    const parsed = JSON.parse(jsonStr);
    if (props.policyType === 'rbac' && parsed.rules) {
      const importedRules: RBACRule[] = parsed.rules.map((rule: any) => ({
        id: rule.id || `rule-${Date.now()}`,
        description: rule.description || '',
        effect: rule.effect || 'allow',
        conditions: Object.entries(rule.conditions || {}).map(([key, value]) => ({
          key,
          value: Array.isArray(value) ? JSON.stringify(value) : String(value),
        })),
      }));
      rules.value = importedRules;
    } else if (props.policyType === 'abac' && parsed.conditions) {
      rules.value = parsed.conditions;
    }
  } catch (error) {
    alert('Invalid JSON format');
    console.error('Error importing JSON:', error);
  }
};

const copyJSON = () => {
  navigator.clipboard.writeText(formattedJSON.value);
  alert('JSON copied to clipboard');
};

onMounted(() => {
  loadTemplates();
});
</script>

<style scoped>
.policy-visual-builder {
  display: grid;
  grid-template-columns: 200px 1fr 300px;
  gap: var(--spacing-md);
  height: 600px;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  overflow: hidden;
}

.builder-toolbar {
  background: var(--color-bg-secondary);
  border-right: var(--border-width-thin) solid var(--border-color-primary);
  padding: var(--spacing-md);
  overflow-y: auto;
}

.toolbar-section h4 {
  margin: 0 0 0.75rem 0;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.template-selector {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.btn-clear-template {
  padding: 0.375rem 0.75rem;
  font-size: 0.75rem;
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-clear-template:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.element-palette {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.palette-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  cursor: grab;
  transition: var(--transition-all);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.palette-item:hover {
  border-color: var(--color-primary);
  background: var(--color-bg-overlay-light);
}

.palette-item:active {
  cursor: grabbing;
}

.palette-icon {
  width: 16px;
  height: 16px;
  color: var(--color-primary);
}

.builder-workspace {
  display: flex;
  flex-direction: column;
  background: var(--color-bg-card);
  overflow-y: auto;
}

.workspace-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.workspace-header h4 {
  margin: 0;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.workspace-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-secondary.small {
  padding: 0.375rem 0.75rem;
  font-size: 0.75rem;
}

.workspace-area {
  flex: 1;
  padding: 1rem;
  min-height: 0;
}

.preview-panel {
  background: var(--color-bg-tertiary);
  border-left: var(--border-width-thin) solid var(--border-color-primary);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.panel-header h4 {
  margin: 0;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.json-preview {
  flex: 1;
  margin: 0;
  padding: var(--spacing-md);
  background: var(--color-bg-primary);
  color: var(--color-success);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-xs);
  line-height: var(--line-height-normal);
  overflow: auto;
  white-space: pre-wrap;
  word-wrap: break-word;
}
</style>
