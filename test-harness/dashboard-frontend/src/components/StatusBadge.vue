<template>
  <span 
    class="status-badge" 
    :class="[
      `badge-${variant}`,
      `status-${status}`,
      { 'badge-sm': size === 'sm', 'badge-lg': size === 'lg' }
    ]"
  >
    <component v-if="icon" :is="icon" class="badge-icon" />
    <span>{{ label || status }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { type LucideIcon } from 'lucide-vue-next';

interface Props {
  status: string;
  label?: string;
  variant?: 'default' | 'success' | 'warning' | 'error' | 'info' | 'muted';
  size?: 'sm' | 'md' | 'lg';
  icon?: LucideIcon;
}

const props = withDefaults(defineProps<Props>(), {
  variant: 'default',
  size: 'md',
});

// Auto-detect variant from status if not explicitly provided
const variant = computed(() => {
  if (props.variant !== 'default') return props.variant;
  
  const statusLower = props.status.toLowerCase();
  if (['success', 'active', 'enabled', 'approved', 'resolved', 'compliant', 'passed'].includes(statusLower)) {
    return 'success';
  }
  if (['warning', 'pending', 'in-progress', 'partial', 'partially_compliant'].includes(statusLower)) {
    return 'warning';
  }
  if (['error', 'failed', 'disabled', 'rejected', 'non_compliant', 'critical'].includes(statusLower)) {
    return 'error';
  }
  if (['info', 'draft', 'not_assessed'].includes(statusLower)) {
    return 'info';
  }
  return 'muted';
});
</script>

<style scoped>
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
  white-space: nowrap;
}

.status-badge.badge-sm {
  padding: var(--spacing-xs) var(--spacing-xs);
  font-size: var(--font-size-xs);
}

.status-badge.badge-lg {
  padding: var(--spacing-sm) var(--spacing-md);
  font-size: var(--font-size-sm);
}

.badge-icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

.status-badge.badge-sm .badge-icon {
  width: 12px;
  height: 12px;
}

.status-badge.badge-lg .badge-icon {
  width: 16px;
  height: 16px;
}

/* Variant-based colors */
.badge-success {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.badge-warning {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.badge-error {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.badge-info {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.badge-muted {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-muted);
}

/* Status-specific overrides */
.status-draft {
  background: var(--border-color-muted);
  color: var(--color-text-secondary);
}

.status-pending {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-approved,
.status-enabled {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-rejected,
.status-disabled {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-open {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-in-progress {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.status-resolved {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-ignored {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-muted);
}
</style>
