<template>
  <div class="policy-diff-viewer">
    <div class="diff-header">
      <div class="header-controls">
        <div class="version-selectors">
          <Dropdown
            v-model="selectedVersion1"
            :options="versionOptions"
            placeholder="Select version 1..."
            class="version-selector"
          />
          <span class="version-separator">vs</span>
          <Dropdown
            v-model="selectedVersion2"
            :options="versionOptions"
            placeholder="Select version 2..."
            class="version-selector"
          />
          <button
            @click="compareVersions"
            :disabled="!canCompare || loading"
            class="btn-primary"
          >
            Compare
          </button>
        </div>
        <div class="view-controls">
          <button
            @click="viewMode = 'split'"
            :class="['btn-view-mode', { active: viewMode === 'split' }]"
          >
            Split View
          </button>
          <button
            @click="viewMode = 'unified'"
            :class="['btn-view-mode', { active: viewMode === 'unified' }]"
          >
            Unified View
          </button>
        </div>
      </div>
      <div v-if="comparison" class="diff-summary">
        <div class="summary-item">
          <span class="summary-label">Total Changes:</span>
          <span class="summary-value">{{ comparison.summary.totalChanges }}</span>
        </div>
        <div class="summary-item added">
          <span class="summary-label">Added:</span>
          <span class="summary-value">{{ comparison.summary.addedFields }}</span>
        </div>
        <div class="summary-item removed">
          <span class="summary-label">Removed:</span>
          <span class="summary-value">{{ comparison.summary.removedFields }}</span>
        </div>
        <div class="summary-item modified">
          <span class="summary-label">Modified:</span>
          <span class="summary-value">{{ comparison.summary.modifiedFields }}</span>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Comparing versions...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
    </div>

    <div v-else-if="comparison" class="diff-content">
      <!-- Split View -->
      <div v-if="viewMode === 'split'" class="split-view">
        <div class="diff-panel">
          <div class="panel-header">
            <h4>Version {{ comparison.version1 }}</h4>
          </div>
          <div class="panel-content">
            <pre class="json-content">{{ formatPolicyForVersion(comparison.version1) }}</pre>
          </div>
        </div>
        <div class="diff-panel">
          <div class="panel-header">
            <h4>Version {{ comparison.version2 }}</h4>
          </div>
          <div class="panel-content">
            <pre class="json-content">{{ formatPolicyForVersion(comparison.version2) }}</pre>
          </div>
        </div>
      </div>

      <!-- Unified View -->
      <div v-else class="unified-view">
        <div class="diff-structure">
          <h4>Structure Changes</h4>
          
          <!-- Metadata Changes -->
          <div v-if="comparison.structureDiff.metadata.changed.length > 0" class="diff-section">
            <h5>Metadata</h5>
            <div
              v-for="change in comparison.structureDiff.metadata.changed"
              :key="change.field"
              class="diff-item modified"
            >
              <span class="diff-field">{{ change.field }}:</span>
              <span class="diff-old">{{ formatValue(change.oldValue) }}</span>
              <span class="diff-arrow">→</span>
              <span class="diff-new">{{ formatValue(change.newValue) }}</span>
            </div>
          </div>

          <!-- Rule Changes -->
          <div v-if="comparison.structureDiff.rules.added.length > 0" class="diff-section">
            <h5>Added Rules</h5>
            <div
              v-for="rule in comparison.structureDiff.rules.added"
              :key="rule.id"
              class="diff-item added"
            >
              <span class="diff-label">+ Rule:</span>
              <pre class="diff-content">{{ JSON.stringify(rule, null, 2) }}</pre>
            </div>
          </div>

          <div v-if="comparison.structureDiff.rules.removed.length > 0" class="diff-section">
            <h5>Removed Rules</h5>
            <div
              v-for="rule in comparison.structureDiff.rules.removed"
              :key="rule.id"
              class="diff-item removed"
            >
              <span class="diff-label">- Rule:</span>
              <pre class="diff-content">{{ JSON.stringify(rule, null, 2) }}</pre>
            </div>
          </div>

          <div v-if="comparison.structureDiff.rules.modified.length > 0" class="diff-section">
            <h5>Modified Rules</h5>
            <div
              v-for="mod in comparison.structureDiff.rules.modified"
              :key="mod.ruleId"
              class="diff-item modified"
            >
              <span class="diff-label">Rule {{ mod.ruleId }}:</span>
              <div
                v-for="change in mod.changes"
                :key="change.field"
                class="diff-change"
              >
                <span class="diff-field">{{ change.field }}:</span>
                <span class="diff-old">{{ formatValue(change.oldValue) }}</span>
                <span class="diff-arrow">→</span>
                <span class="diff-new">{{ formatValue(change.newValue) }}</span>
              </div>
            </div>
          </div>

          <!-- Condition Changes -->
          <div v-if="comparison.structureDiff.conditions.added.length > 0" class="diff-section">
            <h5>Added Conditions</h5>
            <div
              v-for="(cond, index) in comparison.structureDiff.conditions.added"
              :key="index"
              class="diff-item added"
            >
              <span class="diff-label">+ Condition:</span>
              <pre class="diff-content">{{ JSON.stringify(cond, null, 2) }}</pre>
            </div>
          </div>

          <div v-if="comparison.structureDiff.conditions.removed.length > 0" class="diff-section">
            <h5>Removed Conditions</h5>
            <div
              v-for="(cond, index) in comparison.structureDiff.conditions.removed"
              :key="index"
              class="diff-item removed"
            >
              <span class="diff-label">- Condition:</span>
              <pre class="diff-content">{{ JSON.stringify(cond, null, 2) }}</pre>
            </div>
          </div>

          <div v-if="comparison.structureDiff.conditions.modified.length > 0" class="diff-section">
            <h5>Modified Conditions</h5>
            <div
              v-for="mod in comparison.structureDiff.conditions.modified"
              :key="mod.conditionIndex"
              class="diff-item modified"
            >
              <span class="diff-label">Condition {{ mod.conditionIndex }}:</span>
              <div
                v-for="change in mod.changes"
                :key="change.field"
                class="diff-change"
              >
                <span class="diff-field">{{ change.field }}:</span>
                <span class="diff-old">{{ formatValue(change.oldValue) }}</span>
                <span class="diff-arrow">→</span>
                <span class="diff-new">{{ formatValue(change.newValue) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <GitCompare class="empty-icon" />
      <h3>Compare Policy Versions</h3>
      <p>Select two versions to compare and click "Compare"</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { GitCompare, AlertTriangle } from 'lucide-vue-next';
import Dropdown from '../Dropdown.vue';
import axios from 'axios';

interface Props {
  policyId: string;
  versions?: Array<{ version: string; date: Date }>;
}

const props = defineProps<Props>();

interface VersionComparison {
  version1: string;
  version2: string;
  differences: Array<{
    field: string;
    oldValue: any;
    newValue: any;
    changeType: 'added' | 'removed' | 'modified';
  }>;
  summary: {
    totalChanges: number;
    addedFields: number;
    removedFields: number;
    modifiedFields: number;
  };
  structureDiff: {
    rules: {
      added: any[];
      removed: any[];
      modified: Array<{ ruleId: string; changes: any[] }>;
    };
    conditions: {
      added: any[];
      removed: any[];
      modified: Array<{ conditionIndex: number; changes: any[] }>;
    };
    metadata: {
      changed: Array<{ field: string; oldValue: any; newValue: any }>;
    };
  };
  visualDiff: any[];
}

const selectedVersion1 = ref<string>('');
const selectedVersion2 = ref<string>('');
const viewMode = ref<'split' | 'unified'>('unified');
const comparison = ref<VersionComparison | null>(null);
const loading = ref(false);
const error = ref<string>('');

const versionOptions = computed(() => {
  if (props.versions) {
    return props.versions.map(v => ({
      label: `v${v.version} (${new Date(v.date).toLocaleDateString()})`,
      value: v.version,
    }));
  }
  return [];
});

const canCompare = computed(() => {
  return selectedVersion1.value && selectedVersion2.value && selectedVersion1.value !== selectedVersion2.value;
});

const compareVersions = async () => {
  if (!canCompare.value) return;

  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(
      `/api/policies/${props.policyId}/compare/${selectedVersion1.value}/${selectedVersion2.value}`
    );
    comparison.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to compare versions';
    comparison.value = null;
  } finally {
    loading.value = false;
  }
};

const formatValue = (value: any): string => {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

const formatPolicyForVersion = (version: string): string => {
  // This would format the policy JSON for the specific version
  // For now, return a placeholder
  return `Policy version ${version}\n\n[Policy structure would be displayed here]`;
};

// Load versions if not provided
watch(() => props.policyId, async (newId) => {
  if (newId && !props.versions) {
    try {
      const response = await axios.get(`/api/policies/${newId}/versions`);
      // Set versions would be handled by parent component
    } catch (err) {
      console.error('Failed to load versions', err);
    }
  }
}, { immediate: true });
</script>

<style scoped>
.policy-diff-viewer {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--color-bg-primary);
  border-radius: var(--border-radius-md);
}

.diff-header {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.header-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.version-selectors {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.version-selector {
  min-width: 200px;
}

.version-separator {
  color: var(--color-text-secondary);
  font-weight: 500;
}

.view-controls {
  display: flex;
  gap: var(--spacing-xs);
}

.btn-view-mode {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-view-mode:hover {
  background: var(--border-color-muted);
}

.btn-view-mode.active {
  background: var(--color-primary);
  border-color: var(--color-primary);
  color: white;
}

.diff-summary {
  display: flex;
  gap: var(--spacing-md);
  padding-top: var(--spacing-sm);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.summary-item {
  display: flex;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
}

.summary-label {
  color: var(--color-text-secondary);
}

.summary-value {
  font-weight: 600;
  color: var(--color-text-primary);
}

.summary-item.added .summary-value {
  color: var(--color-success);
}

.summary-item.removed .summary-value {
  color: var(--color-error);
}

.summary-item.modified .summary-value {
  color: var(--color-warning);
}

.diff-content {
  flex: 1;
  overflow: auto;
  padding: var(--spacing-md);
}

.split-view {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
  height: 100%;
}

.diff-panel {
  display: flex;
  flex-direction: column;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  overflow: hidden;
}

.panel-header {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-secondary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.panel-header h4 {
  margin: 0;
  font-size: var(--font-size-sm);
  font-weight: 600;
}

.panel-content {
  flex: 1;
  overflow: auto;
  padding: var(--spacing-md);
}

.json-content {
  margin: 0;
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: var(--font-size-xs);
  line-height: 1.6;
  color: var(--color-text-primary);
}

.unified-view {
  max-width: 100%;
}

.diff-structure {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.diff-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.diff-section h5 {
  margin: 0;
  font-size: var(--font-size-sm);
  font-weight: 600;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.diff-item {
  padding: var(--spacing-sm) var(--spacing-md);
  border-left: 3px solid;
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-secondary);
}

.diff-item.added {
  border-color: var(--color-success);
  background: rgba(var(--color-success-rgb), 0.1);
}

.diff-item.removed {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.1);
}

.diff-item.modified {
  border-color: var(--color-warning);
  background: rgba(var(--color-warning-rgb), 0.1);
}

.diff-label {
  font-weight: 600;
  margin-right: var(--spacing-sm);
}

.diff-field {
  font-weight: 500;
  color: var(--color-text-secondary);
}

.diff-old {
  color: var(--color-error);
  text-decoration: line-through;
  margin: 0 var(--spacing-xs);
}

.diff-new {
  color: var(--color-success);
  margin: 0 var(--spacing-xs);
}

.diff-arrow {
  color: var(--color-text-secondary);
  margin: 0 var(--spacing-xs);
}

.diff-content {
  margin-top: var(--spacing-xs);
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: var(--font-size-xs);
  white-space: pre-wrap;
}

.diff-change {
  margin-left: var(--spacing-md);
  margin-top: var(--spacing-xs);
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  min-height: 400px;
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon,
.empty-icon {
  width: 48px;
  height: 48px;
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}
</style>
