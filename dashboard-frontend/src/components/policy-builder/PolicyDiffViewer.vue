<template>
  <div class="policy-diff-viewer">
    <div class="diff-header">
      <h3>Policy Version Comparison</h3>
      <div class="version-selectors">
        <select v-model="selectedVersion1">
          <option v-for="version in versions" :key="version" :value="version">
            {{ version }}
          </option>
        </select>
        <span>vs</span>
        <select v-model="selectedVersion2">
          <option v-for="version in versions" :key="version" :value="version">
            {{ version }}
          </option>
        </select>
        <button @click="compareVersions" class="btn-primary">Compare</button>
      </div>
    </div>

    <div v-if="diff" class="diff-content">
      <div class="diff-summary">
        <div class="summary-item">
          <span class="summary-label">Added:</span>
          <span class="summary-value added">{{ diff.summary.added }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Modified:</span>
          <span class="summary-value modified">{{ diff.summary.modified }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Deleted:</span>
          <span class="summary-value deleted">{{ diff.summary.deleted }}</span>
        </div>
      </div>

      <div class="changes-list">
        <div
          v-for="(change, index) in diff.changes"
          :key="index"
          class="change-item"
          :class="change.type"
        >
          <div class="change-header">
            <span class="change-type">{{ change.type }}</span>
            <span class="change-path">{{ change.path }}</span>
          </div>
          <div class="change-description">{{ change.description }}</div>
          <div v-if="change.oldValue !== undefined" class="change-old">
            <strong>Old:</strong> {{ formatValue(change.oldValue) }}
          </div>
          <div v-if="change.newValue !== undefined" class="change-new">
            <strong>New:</strong> {{ formatValue(change.newValue) }}
          </div>
        </div>
      </div>
    </div>

    <div v-else class="no-diff">
      <p>Select two versions to compare</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { policyBuilderService } from '../../services/policy-builder.service';
import type { PolicyDiff } from '../../types/policy-builder';

const props = defineProps<{
  policyId: string;
  versions: string[];
}>();

const selectedVersion1 = ref('');
const selectedVersion2 = ref('');
const diff = ref<PolicyDiff | null>(null);

const compareVersions = async () => {
  if (!selectedVersion1.value || !selectedVersion2.value) {
    alert('Please select both versions');
    return;
  }

  try {
    diff.value = await policyBuilderService.compareVersions(
      props.policyId,
      selectedVersion1.value,
      selectedVersion2.value
    );
  } catch (error) {
    console.error('Failed to compare versions:', error);
    alert('Failed to compare versions');
  }
};

const formatValue = (value: any): string => {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
};

onMounted(() => {
  if (props.versions.length >= 2) {
    selectedVersion1.value = props.versions[0];
    selectedVersion2.value = props.versions[1];
  }
});
</script>

<style scoped>
.policy-diff-viewer {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.diff-header {
  padding: 1rem;
  border-bottom: 1px solid #e0e0e0;
}

.version-selectors {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-top: 1rem;
}

.diff-content {
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
}

.diff-summary {
  display: flex;
  gap: 2rem;
  padding: 1rem;
  background: #f7fafc;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.summary-item {
  display: flex;
  flex-direction: column;
}

.summary-label {
  font-size: 0.875rem;
  color: #718096;
}

.summary-value {
  font-size: 1.5rem;
  font-weight: bold;
}

.summary-value.added {
  color: #48bb78;
}

.summary-value.modified {
  color: #ed8936;
}

.summary-value.deleted {
  color: #f56565;
}

.changes-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.change-item {
  padding: 1rem;
  border-left: 4px solid #e0e0e0;
  background: white;
  border-radius: 4px;
}

.change-item.added {
  border-left-color: #48bb78;
  background: #f0fff4;
}

.change-item.modified {
  border-left-color: #ed8936;
  background: #fffaf0;
}

.change-item.deleted {
  border-left-color: #f56565;
  background: #fff5f5;
}

.change-header {
  display: flex;
  gap: 1rem;
  margin-bottom: 0.5rem;
}

.change-type {
  text-transform: uppercase;
  font-weight: bold;
  font-size: 0.75rem;
}

.change-path {
  font-family: monospace;
  color: #718096;
}

.change-description {
  margin-bottom: 0.5rem;
}

.change-old,
.change-new {
  padding: 0.5rem;
  margin-top: 0.5rem;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.875rem;
}

.change-old {
  background: #fff5f5;
  color: #c53030;
}

.change-new {
  background: #f0fff4;
  color: #22543d;
}
</style>
