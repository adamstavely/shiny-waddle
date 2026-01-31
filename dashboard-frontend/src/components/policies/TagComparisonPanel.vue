<template>
  <div class="tag-comparison-panel">
    <div class="panel-header">
      <h3>Data Tag Comparison</h3>
      <div class="header-actions">
        <button @click="loadComparison" :disabled="loading" class="btn-secondary small">
          Refresh
        </button>
        <button @click="loadGuidance" :disabled="loading || !comparison" class="btn-primary small">
          View Guidance
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Comparing tags...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadComparison" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="comparison" class="comparison-content">
      <!-- Compliance Status -->
      <div class="compliance-status" :class="comparison.compliance.isCompliant ? 'compliant' : 'non-compliant'">
        <div class="status-icon">
          <CheckCircle2 v-if="comparison.compliance.isCompliant" class="icon" />
          <XCircle v-else class="icon" />
        </div>
        <div class="status-details">
          <h4>{{ comparison.compliance.isCompliant ? 'Tags Compliant' : 'Tags Non-Compliant' }}</h4>
          <p>
            {{ comparison.compliance.missingCount }} missing,
            {{ comparison.compliance.incorrectCount }} incorrect
          </p>
        </div>
      </div>

      <!-- Tag Comparison Table -->
      <div class="tags-comparison">
        <h4>Tag Comparison</h4>
        <div class="comparison-table">
          <div class="table-header">
            <div class="header-cell">Tag Key</div>
            <div class="header-cell">Expected Value</div>
            <div class="header-cell">Actual Value</div>
            <div class="header-cell">Status</div>
            <div class="header-cell">Actions</div>
          </div>

          <!-- Expected Tags -->
          <div
            v-for="(expectedValue, key) in comparison.expectedTags"
            :key="key"
            class="table-row"
            :class="getRowClass(key)"
          >
            <div class="cell tag-key">{{ key }}</div>
            <div class="cell expected-value">{{ expectedValue }}</div>
            <div class="cell actual-value">
              <span v-if="comparison.actualTags[key]">{{ comparison.actualTags[key] }}</span>
              <span v-else class="missing">Not set</span>
            </div>
            <div class="cell status">
              <span :class="['status-badge', getStatusClass(key)]">
                {{ getStatusText(key) }}
              </span>
            </div>
            <div class="cell actions">
              <button
                v-if="!comparison.actualTags[key] || comparison.actualTags[key] !== expectedValue"
                @click="showUpdateDialog(key, expectedValue)"
                class="btn-update"
              >
                Update
              </button>
            </div>
          </div>

          <!-- Extra Tags (in actual but not expected) -->
          <div
            v-for="key in comparison.extraTags"
            :key="`extra-${key}`"
            class="table-row extra-tag"
          >
            <div class="cell tag-key">{{ key }}</div>
            <div class="cell expected-value">—</div>
            <div class="cell actual-value">{{ comparison.actualTags[key] }}</div>
            <div class="cell status">
              <span class="status-badge status-extra">Extra</span>
            </div>
            <div class="cell actions">
              <button @click="showRemoveDialog(key)" class="btn-remove">Remove</button>
            </div>
          </div>

          <div v-if="Object.keys(comparison.expectedTags).length === 0 && comparison.extraTags.length === 0" class="empty-tags">
            <p>No tags to compare</p>
          </div>
        </div>
      </div>

      <!-- Summary -->
      <div class="comparison-summary">
        <div class="summary-item">
          <span class="summary-label">Total Expected:</span>
          <span class="summary-value">{{ Object.keys(comparison.expectedTags).length }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Missing:</span>
          <span class="summary-value error">{{ comparison.compliance.missingCount }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Incorrect:</span>
          <span class="summary-value warning">{{ comparison.compliance.incorrectCount }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Extra:</span>
          <span class="summary-value info">{{ comparison.extraTags.length }}</span>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <Tags class="empty-icon" />
      <h3>Tag Comparison</h3>
      <p>Select a resource to compare tags</p>
    </div>

    <!-- Guidance Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showGuidanceModal && guidance" class="modal-overlay" @click="showGuidanceModal = false">
          <div class="modal-content guidance-modal" @click.stop>
            <div class="modal-header">
              <h2>Tag Update Guidance</h2>
              <button @click="showGuidanceModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="guidance-content">
                <div class="guidance-header">
                  <div class="priority-badge" :class="`priority-${guidance.priority}`">
                    {{ guidance.priority.toUpperCase() }} Priority
                  </div>
                  <div class="estimated-time">
                    Estimated Time: {{ guidance.estimatedTime }}
                  </div>
                </div>

                <div class="actions-list">
                  <div
                    v-for="(action, index) in guidance.actions"
                    :key="index"
                    class="action-item"
                  >
                    <div class="action-header">
                      <span class="action-type" :class="`type-${action.type}`">
                        {{ action.type.toUpperCase() }}
                      </span>
                      <h4>{{ action.tag }}: {{ action.value }}</h4>
                    </div>
                    <p class="action-reason">{{ action.reason }}</p>
                    <ol class="action-steps">
                      <li v-for="(step, stepIndex) in action.steps" :key="stepIndex">
                        {{ step }}
                      </li>
                    </ol>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Tags, AlertTriangle, CheckCircle2, XCircle, X } from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  resourceId: string;
  policyId?: string;
}

const props = defineProps<Props>();

interface TagComparison {
  resourceId: string;
  resourceName: string;
  expectedTags: Record<string, string>;
  actualTags: Record<string, string>;
  missingTags: string[];
  incorrectTags: Array<{
    key: string;
    expected: string;
    actual: string;
  }>;
  extraTags: string[];
  compliance: {
    isCompliant: boolean;
    missingCount: number;
    incorrectCount: number;
  };
}

interface TagUpdateGuidance {
  resourceId: string;
  actions: Array<{
    type: 'add' | 'update' | 'remove';
    tag: string;
    value: string;
    reason: string;
    steps: string[];
  }>;
  estimatedTime: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

const comparison = ref<TagComparison | null>(null);
const guidance = ref<TagUpdateGuidance | null>(null);
const loading = ref(false);
const error = ref<string>('');
const showGuidanceModal = ref(false);

const getRowClass = (key: string): string => {
  if (!comparison.value) return '';
  if (comparison.value.missingTags.includes(key)) return 'row-missing';
  if (comparison.value.incorrectTags.some(t => t.key === key)) return 'row-incorrect';
  return 'row-compliant';
};

const getStatusClass = (key: string): string => {
  if (!comparison.value) return '';
  if (comparison.value.missingTags.includes(key)) return 'status-missing';
  if (comparison.value.incorrectTags.some(t => t.key === key)) return 'status-incorrect';
  return 'status-compliant';
};

const getStatusText = (key: string): string => {
  if (!comparison.value) return '';
  if (comparison.value.missingTags.includes(key)) return 'Missing';
  if (comparison.value.incorrectTags.some(t => t.key === key)) return 'Incorrect';
  return 'Compliant';
};

const loadComparison = async () => {
  if (!props.resourceId) return;

  loading.value = true;
  error.value = '';

  try {
    const url = `/api/policies/tags/compare/${props.resourceId}`;
    const params = props.policyId ? { policyId: props.policyId } : {};
    const response = await axios.get(url, { params });
    comparison.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load tag comparison';
    comparison.value = null;
  } finally {
    loading.value = false;
  }
};

const loadGuidance = async () => {
  if (!props.resourceId) return;

  loading.value = true;
  error.value = '';

  try {
    const url = `/api/policies/tags/guidance/${props.resourceId}`;
    const params = props.policyId ? { policyId: props.policyId } : {};
    const response = await axios.get(url, { params });
    guidance.value = response.data;
    showGuidanceModal.value = true;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load guidance';
  } finally {
    loading.value = false;
  }
};

const showUpdateDialog = (key: string, value: string) => {
  // In production, this would open a dialog to update the tag
  // For now, just show guidance
  loadGuidance();
};

const showRemoveDialog = (key: string) => {
  // In production, this would open a confirmation dialog
  console.log(`Remove tag: ${key}`);
};

watch(() => props.resourceId, () => {
  if (props.resourceId) {
    loadComparison();
  }
}, { immediate: true });
</script>

<style scoped>
.tag-comparison-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--color-bg-primary);
  border-radius: var(--border-radius-md);
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.panel-header h3 {
  margin: 0;
  font-size: var(--font-size-lg);
  font-weight: 600;
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.comparison-content {
  flex: 1;
  overflow: auto;
  padding: var(--spacing-md);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.compliance-status {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  border: 2px solid;
}

.compliance-status.compliant {
  background: rgba(var(--color-success-rgb), 0.1);
  border-color: var(--color-success);
}

.compliance-status.non-compliant {
  background: rgba(var(--color-error-rgb), 0.1);
  border-color: var(--color-error);
}

.status-icon .icon {
  width: 32px;
  height: 32px;
}

.compliance-status.compliant .status-icon .icon {
  color: var(--color-success);
}

.compliance-status.non-compliant .status-icon .icon {
  color: var(--color-error);
}

.status-details h4 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.status-details p {
  margin: 0;
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.tags-comparison h4 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.comparison-table {
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  overflow: hidden;
}

.table-header {
  display: grid;
  grid-template-columns: 2fr 2fr 2fr 1fr 1fr;
  background: var(--color-bg-secondary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  font-weight: 600;
  font-size: var(--font-size-sm);
}

.header-cell {
  padding: var(--spacing-sm) var(--spacing-md);
  text-align: left;
}

.table-row {
  display: grid;
  grid-template-columns: 2fr 2fr 2fr 1fr 1fr;
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  transition: background 0.2s;
}

.table-row:hover {
  background: var(--color-bg-overlay-light);
}

.table-row.row-compliant {
  background: rgba(var(--color-success-rgb), 0.05);
}

.table-row.row-missing {
  background: rgba(var(--color-error-rgb), 0.05);
}

.table-row.row-incorrect {
  background: rgba(var(--color-warning-rgb), 0.05);
}

.table-row.extra-tag {
  background: rgba(var(--color-text-secondary-rgb), 0.05);
}

.cell {
  padding: var(--spacing-sm) var(--spacing-md);
  display: flex;
  align-items: center;
}

.tag-key {
  font-weight: 500;
  font-family: 'Monaco', 'Courier New', monospace;
}

.expected-value,
.actual-value {
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: var(--font-size-sm);
}

.actual-value .missing {
  color: var(--color-error);
  font-style: italic;
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.status-badge.status-compliant {
  background: var(--color-success);
  color: white;
}

.status-badge.status-missing {
  background: var(--color-error);
  color: white;
}

.status-badge.status-incorrect {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.status-badge.status-extra {
  background: var(--color-text-secondary);
  color: white;
}

.btn-update,
.btn-remove {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  cursor: pointer;
  border: var(--border-width-thin) solid;
  transition: var(--transition-all);
}

.btn-update {
  background: var(--color-primary);
  border-color: var(--color-primary);
  color: white;
}

.btn-update:hover {
  opacity: 0.9;
}

.btn-remove {
  background: transparent;
  border-color: var(--color-error);
  color: var(--color-error);
}

.btn-remove:hover {
  background: var(--color-error);
  color: white;
}

.comparison-summary {
  display: flex;
  gap: var(--spacing-lg);
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.summary-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.summary-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.summary-value {
  font-size: var(--font-size-lg);
  font-weight: 700;
}

.summary-value.error {
  color: var(--color-error);
}

.summary-value.warning {
  color: var(--color-warning);
}

.summary-value.info {
  color: var(--color-text-secondary);
}

.empty-tags {
  padding: var(--spacing-xl);
  text-align: center;
  color: var(--color-text-secondary);
}

.guidance-modal {
  max-width: 800px;
  width: 90vw;
}

.guidance-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.guidance-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.priority-badge {
  padding: var(--spacing-xs) var(--spacing-md);
  border-radius: var(--border-radius-sm);
  font-weight: 600;
  font-size: var(--font-size-sm);
}

.priority-critical,
.priority-high {
  background: var(--color-error);
  color: white;
}

.priority-medium {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.priority-low {
  background: var(--color-text-secondary);
  color: white;
}

.estimated-time {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.actions-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.action-item {
  padding: var(--spacing-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  background: var(--color-bg-secondary);
}

.action-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.action-type {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.type-add {
  background: var(--color-success);
  color: white;
}

.type-update {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.type-remove {
  background: var(--color-error);
  color: white;
}

.action-header h4 {
  margin: 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.action-reason {
  margin: var(--spacing-sm) 0;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.action-steps {
  margin: var(--spacing-sm) 0 0 var(--spacing-md);
  padding-left: var(--spacing-md);
}

.action-steps li {
  margin-bottom: var(--spacing-xs);
  line-height: 1.6;
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

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: 500;
}
</style>
