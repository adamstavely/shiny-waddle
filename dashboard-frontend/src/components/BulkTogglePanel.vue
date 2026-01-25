<template>
  <div class="bulk-toggle-panel">
    <div class="panel-header">
      <h3 class="panel-title">Bulk Toggle</h3>
      <button @click="showPanel = !showPanel" class="toggle-button">
        <ChevronDown v-if="!showPanel" class="icon" />
        <ChevronUp v-else class="icon" />
      </button>
    </div>
    
    <div v-if="showPanel" class="panel-content">
      <div class="bulk-actions">
        <button @click="selectAll" class="action-btn">Select All</button>
        <button @click="deselectAll" class="action-btn">Deselect All</button>
        <button @click="enableSelected" class="action-btn primary" :class="{ active: intendedAction === 'enable' }">Enable Selected</button>
        <button @click="disableSelected" class="action-btn danger" :class="{ active: intendedAction === 'disable' }">Disable Selected</button>
      </div>
      
      <div class="items-list">
        <label
          v-for="item in items"
          :key="item.id"
          class="bulk-item"
        >
          <input
            type="checkbox"
            v-model="selectedItems"
            :value="item.id"
          />
          <span class="item-name">{{ item.name }}</span>
          <span class="item-status" :class="item.enabled ? 'enabled' : 'disabled'">
            {{ item.enabled ? 'Enabled' : 'Disabled' }}
          </span>
        </label>
      </div>

      <div class="reason-section">
        <label class="reason-label">Reason (optional)</label>
        <textarea
          v-model="bulkReason"
          class="reason-input"
          placeholder="Enter a reason for this bulk operation..."
          rows="3"
        ></textarea>
      </div>
      
      <div class="panel-actions">
        <button @click="applyBulkToggle" class="btn-primary" :disabled="loading || selectedItems.length === 0 || !intendedAction">
          {{ loading ? 'Applying...' : 'Apply Changes' }}
        </button>
        <button @click="cancel" class="btn-secondary">Cancel</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { ChevronDown, ChevronUp } from 'lucide-vue-next';

interface Props {
  items: Array<{
    id: string;
    name: string;
    enabled: boolean;
  }>;
  loading?: boolean;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: 'bulk-toggle', items: Array<{ id: string; enabled: boolean; reason?: string }>): void;
  (e: 'cancel'): void;
}>();

const showPanel = ref(false);
const selectedItems = ref<string[]>([]);
const intendedAction = ref<'enable' | 'disable' | null>(null);
const bulkReason = ref('');

const selectAll = () => {
  selectedItems.value = props.items.map(item => item.id);
};

const deselectAll = () => {
  selectedItems.value = [];
  intendedAction.value = null;
};

const enableSelected = () => {
  if (selectedItems.value.length === 0) {
    return;
  }
  intendedAction.value = 'enable';
};

const disableSelected = () => {
  if (selectedItems.value.length === 0) {
    return;
  }
  intendedAction.value = 'disable';
};

const applyBulkToggle = () => {
  if (!intendedAction.value || selectedItems.value.length === 0) {
    return;
  }

  const changes = selectedItems.value.map(id => {
    const item = props.items.find(i => i.id === id);
    return {
      id,
      enabled: intendedAction.value === 'enable' ? true : false,
      reason: bulkReason.value || undefined,
    };
  });
  
  emit('bulk-toggle', changes);
  selectedItems.value = [];
  intendedAction.value = null;
  bulkReason.value = '';
  showPanel.value = false;
};

const cancel = () => {
  selectedItems.value = [];
  intendedAction.value = null;
  bulkReason.value = '';
  showPanel.value = false;
  emit('cancel');
};
</script>

<style scoped>
.bulk-toggle-panel {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 24px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.panel-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.toggle-button {
  background: transparent;
  border: none;
  color: #4facfe;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
}

.icon {
  width: 20px;
  height: 20px;
}

.panel-content {
  margin-top: 16px;
}

.bulk-actions {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.action-btn {
  padding: 8px 16px;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  background: transparent;
  color: #4facfe;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-btn.primary {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.action-btn.danger {
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.action-btn.danger:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.action-btn.active {
  background: rgba(79, 172, 254, 0.3);
  border-color: rgba(79, 172, 254, 0.6);
}

.action-btn.danger.active {
  background: rgba(252, 129, 129, 0.2);
  border-color: rgba(252, 129, 129, 0.6);
}

.items-list {
  max-height: 300px;
  overflow-y: auto;
  margin-bottom: 16px;
}

.reason-section {
  margin-bottom: 16px;
}

.reason-label {
  display: block;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
  margin-bottom: 8px;
}

.reason-input {
  width: 100%;
  padding: 10px;
  background: rgba(79, 172, 254, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  font-family: inherit;
  resize: vertical;
  transition: border-color 0.2s;
}

.reason-input:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.6);
  background: rgba(79, 172, 254, 0.08);
}

.reason-input::placeholder {
  color: #a0aec0;
}

.bulk-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: rgba(79, 172, 254, 0.05);
  border-radius: 6px;
  margin-bottom: 8px;
  cursor: pointer;
  transition: background 0.2s;
}

.bulk-item:hover {
  background: rgba(79, 172, 254, 0.1);
}

.bulk-item input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.item-name {
  flex: 1;
  color: #ffffff;
  font-size: 0.875rem;
}

.item-status {
  font-size: 0.75rem;
  padding: 4px 8px;
  border-radius: 4px;
  font-weight: 600;
}

.item-status.enabled {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.item-status.disabled {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.panel-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

.btn-primary {
  padding: 10px 20px;
  background: #4facfe;
  color: #ffffff;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: background 0.2s;
}

.btn-primary:hover:not(:disabled) {
  background: #3d8bfe;
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  padding: 10px 20px;
  background: transparent;
  color: #a0aec0;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}
</style>

