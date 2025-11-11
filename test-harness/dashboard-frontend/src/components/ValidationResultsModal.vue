<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content large" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <FileText class="modal-title-icon" />
              <h2>Validation Results - {{ target?.name }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="results-filters">
              <Dropdown
                v-model="filterStatus"
                :options="statusOptions"
                placeholder="All Statuses"
                class="filter-dropdown"
              />
              <Dropdown
                v-model="filterSeverity"
                :options="severityOptions"
                placeholder="All Severities"
                class="filter-dropdown"
              />
            </div>

            <div class="results-list">
              <div
                v-for="result in filteredResults"
                :key="result.id"
                class="result-card"
                :class="`result-${result.status}`"
              >
                <div class="result-header">
                  <div class="result-title-row">
                    <h4 class="result-rule">{{ getRuleName(result.ruleId) }}</h4>
                    <span class="result-status" :class="`status-${result.status}`">
                      {{ result.status }}
                    </span>
                  </div>
                  <div class="result-meta">
                    <span class="result-time">{{ formatDate(result.timestamp) }}</span>
                  </div>
                </div>
                <div class="result-message">
                  {{ result.message }}
                </div>
                <div v-if="result.details" class="result-details">
                  <pre>{{ JSON.stringify(result.details, null, 2) }}</pre>
                </div>
              </div>
            </div>

            <div v-if="filteredResults.length === 0" class="empty-results">
              <FileText class="empty-icon" />
              <p>No validation results found</p>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { FileText, X } from 'lucide-vue-next';
import { Teleport } from 'vue';
import Dropdown from './Dropdown.vue';

const props = defineProps<{
  show: boolean;
  target: any | null;
  results: any[];
}>();

const emit = defineEmits<{
  close: [];
}>();

const filterStatus = ref('');
const filterSeverity = ref('');

const statusOptions = [
  { label: 'All Statuses', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Warning', value: 'warning' },
];

const severityOptions = [
  { label: 'All Severities', value: '' },
  { label: 'Low', value: 'low' },
  { label: 'Medium', value: 'medium' },
  { label: 'High', value: 'high' },
  { label: 'Critical', value: 'critical' },
];

const filteredResults = computed(() => {
  return props.results.filter(result => {
    const matchesStatus = !filterStatus.value || result.status === filterStatus.value;
    // Note: severity would need to be looked up from the rule
    return matchesStatus;
  });
});

const getRuleName = (ruleId: string): string => {
  // In a real implementation, this would look up the rule name
  return `Rule ${ruleId.substring(0, 8)}`;
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};
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

.results-filters {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
}

.filter-dropdown {
  min-width: 150px;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.result-card {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  border-left: 4px solid;
}

.result-card.result-passed {
  border-left-color: #22c55e;
}

.result-card.result-failed {
  border-left-color: #fc8181;
}

.result-card.result-warning {
  border-left-color: #fbbf24;
}

.result-header {
  margin-bottom: 12px;
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.result-rule {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.result-status {
  padding: 4px 12px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.result-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.result-time {
  color: #718096;
}

.result-message {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 12px;
  line-height: 1.5;
}

.result-details {
  margin-top: 12px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.result-details pre {
  margin: 0;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #a0aec0;
  overflow-x: auto;
}

.empty-results {
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

.empty-results p {
  color: #a0aec0;
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

