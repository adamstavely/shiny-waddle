<template>
  <div class="validator-card" :class="{ disabled: !validator.enabled }">
    <div class="validator-header">
      <div class="validator-title-row">
        <h3 class="validator-name">{{ validator.name }}</h3>
        <span class="validator-status" :class="validator.enabled ? 'status-enabled' : 'status-disabled'">
          {{ validator.enabled ? 'Enabled' : 'Disabled' }}
        </span>
      </div>
      <p class="validator-id">ID: {{ validator.id }}</p>
    </div>

    <div class="validator-description">
      {{ validator.description }}
    </div>

    <div class="validator-details">
      <div class="detail-item">
        <span class="detail-label">Version</span>
        <span class="detail-value">{{ validator.version }}</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Test Type</span>
        <span class="detail-value">{{ validator.testType }}</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Tests Executed</span>
        <span class="detail-value">{{ validator.testCount || 0 }}</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Success Rate</span>
        <span class="detail-value" :class="getSuccessRateClass(validator)">
          {{ getSuccessRate(validator) }}%
        </span>
      </div>
      <div class="detail-item" v-if="validator.lastRunAt">
        <span class="detail-label">Last Run</span>
        <span class="detail-value">{{ formatDate(validator.lastRunAt) }}</span>
      </div>
    </div>

    <div class="validator-tags" v-if="validator.metadata?.tags && validator.metadata.tags.length > 0">
      <span
        v-for="tag in validator.metadata.tags"
        :key="tag"
        class="tag"
      >
        {{ tag }}
      </span>
    </div>

    <div class="validator-actions">
      <button @click="$emit('view', validator)" class="action-btn view-btn">
        <Eye class="action-icon" />
        View Details
      </button>
      <button
        @click="$emit('toggle', validator)"
        class="action-btn toggle-btn"
        :class="validator.enabled ? 'disable-btn' : 'enable-btn'"
      >
        <component :is="validator.enabled ? PowerOff : Power" class="action-icon" />
        {{ validator.enabled ? 'Disable' : 'Enable' }}
      </button>
      <button @click="$emit('test', validator)" class="action-btn test-btn">
        <TestTube class="action-icon" />
        Test
      </button>
      <button @click="$emit('delete', validator)" class="action-btn delete-btn">
        <Trash2 class="action-icon" />
        Delete
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Eye, Power, PowerOff, TestTube, Trash2 } from 'lucide-vue-next';

interface Validator {
  id: string;
  name: string;
  description: string;
  testType: string;
  version: string;
  enabled: boolean;
  testCount?: number;
  successCount?: number;
  failureCount?: number;
  lastRunAt?: Date | string;
  metadata?: {
    tags?: string[];
  };
}

defineProps<{
  validator: Validator;
}>();

defineEmits<{
  view: [validator: Validator];
  toggle: [validator: Validator];
  test: [validator: Validator];
  delete: [validator: Validator];
}>();

const getSuccessRate = (validator: Validator): number => {
  if (!validator.testCount || validator.testCount === 0) return 0;
  const success = validator.successCount || 0;
  return Math.round((success / validator.testCount) * 100);
};

const getSuccessRateClass = (validator: Validator): string => {
  const rate = getSuccessRate(validator);
  if (rate >= 90) return 'rate-high';
  if (rate >= 70) return 'rate-medium';
  return 'rate-low';
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return d.toLocaleDateString();
};
</script>

<style scoped>
.validator-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.validator-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.validator-card.disabled {
  opacity: var(--opacity-disabled);
}

.validator-header {
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.validator-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--spacing-sm);
}

.validator-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.validator-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.status-enabled {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-disabled {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-muted);
}

.validator-id {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
  font-family: 'Courier New', monospace;
  margin: 0;
}

.validator-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
  line-height: 1.5;
}

.validator-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-lg);
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: var(--font-size-sm);
}

.detail-label {
  color: var(--color-text-muted);
  font-weight: var(--font-weight-medium);
}

.detail-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.rate-high {
  color: var(--color-success);
}

.rate-medium {
  color: var(--color-warning);
}

.rate-low {
  color: var(--color-error);
}

.validator-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.tag {
  padding: var(--spacing-xs) 10px;
  border-radius: var(--border-radius-sm);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.validator-actions {
  display: flex;
  gap: var(--spacing-sm);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-sm);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.view-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.enable-btn:hover {
  background: var(--color-success-bg);
  border-color: var(--color-success);
  color: var(--color-success);
}

.disable-btn:hover {
  background: var(--color-warning-bg);
  border-color: var(--color-warning);
  color: var(--color-warning);
}

.test-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.delete-btn:hover {
  background: var(--color-error-bg);
  border-color: var(--color-error);
  color: var(--color-error);
}

.action-icon {
  width: 16px;
  height: 16px;
}
</style>

