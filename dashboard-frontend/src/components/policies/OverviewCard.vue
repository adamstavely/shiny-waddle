<template>
  <div class="overview-card" :class="`status-${status}`">
    <div class="card-icon">
      <component :is="iconComponent" class="icon" />
    </div>
    <div class="card-content">
      <div class="card-value">{{ value }}</div>
      <div class="card-label">{{ title }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { Shield, Gauge, AlertCircle, AlertTriangle } from 'lucide-vue-next';

interface Props {
  title: string;
  value: string | number;
  icon: string;
  status?: 'success' | 'warning' | 'error' | 'info';
}

const props = withDefaults(defineProps<Props>(), {
  status: 'info'
});

const iconComponent = computed(() => {
  const iconMap: Record<string, any> = {
    Shield,
    Gauge,
    AlertCircle,
    AlertTriangle,
  };
  return iconMap[props.icon] || Shield;
});
</script>

<style scoped>
.overview-card {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  transition: var(--transition-all);
}

.overview-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.overview-card.status-success {
  border-color: var(--color-success);
  background: linear-gradient(135deg, rgba(var(--color-success-rgb), 0.1), rgba(var(--color-success-rgb), 0.05));
}

.overview-card.status-warning {
  border-color: var(--color-warning);
  background: linear-gradient(135deg, rgba(var(--color-warning-rgb), 0.1), rgba(var(--color-warning-rgb), 0.05));
}

.overview-card.status-error {
  border-color: var(--color-error);
  background: linear-gradient(135deg, rgba(var(--color-error-rgb), 0.1), rgba(var(--color-error-rgb), 0.05));
}

.card-icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--border-radius-md);
  background: var(--color-bg-overlay-light);
}

.card-icon .icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.overview-card.status-success .card-icon .icon {
  color: var(--color-success);
}

.overview-card.status-warning .card-icon .icon {
  color: var(--color-warning);
}

.overview-card.status-error .card-icon .icon {
  color: var(--color-error);
}

.card-content {
  flex: 1;
}

.card-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  line-height: 1.2;
  margin-bottom: var(--spacing-xs);
}

.card-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: var(--letter-spacing-wide);
}
</style>
