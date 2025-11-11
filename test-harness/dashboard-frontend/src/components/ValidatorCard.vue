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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.2s;
}

.validator-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.validator-card.disabled {
  opacity: 0.6;
}

.validator-header {
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.validator-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.validator-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.validator-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-enabled {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-disabled {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.validator-id {
  font-size: 0.875rem;
  color: #718096;
  font-family: 'Courier New', monospace;
  margin: 0;
}

.validator-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 16px;
  line-height: 1.5;
}

.validator-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 16px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.875rem;
}

.detail-label {
  color: #718096;
  font-weight: 500;
}

.detail-value {
  color: #ffffff;
  font-weight: 500;
}

.rate-high {
  color: #22c55e;
}

.rate-medium {
  color: #fbbf24;
}

.rate-low {
  color: #fc8181;
}

.validator-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.tag {
  padding: 4px 10px;
  border-radius: 6px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.validator-actions {
  display: flex;
  gap: 8px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.view-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.enable-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.disable-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.test-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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
</style>

