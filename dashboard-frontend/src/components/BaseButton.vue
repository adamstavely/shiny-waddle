<template>
  <component
    :is="tag"
    :type="type"
    :disabled="disabled || loading"
    :class="[
      'base-button',
      `btn-${variant}`,
      `btn-${size}`,
      {
        'btn-icon-only': iconOnly,
        'btn-loading': loading,
        'btn-full-width': fullWidth
      }
    ]"
    @click="handleClick"
  >
    <div v-if="loading" class="btn-spinner"></div>
    <component v-if="icon && !loading" :is="icon" class="btn-icon" :class="{ 'icon-left': label, 'icon-right': iconRight }" />
    <span v-if="label" class="btn-label">{{ label }}</span>
    <slot />
  </component>
</template>

<script setup lang="ts">
import { type LucideIcon } from 'lucide-vue-next';

interface Props {
  label?: string;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
  size?: 'sm' | 'md' | 'lg';
  type?: 'button' | 'submit' | 'reset';
  tag?: 'button' | 'a';
  icon?: LucideIcon;
  iconRight?: boolean;
  iconOnly?: boolean;
  disabled?: boolean;
  loading?: boolean;
  fullWidth?: boolean;
  href?: string;
}

const props = withDefaults(defineProps<Props>(), {
  variant: 'primary',
  size: 'md',
  type: 'button',
  tag: 'button',
  iconRight: false,
  iconOnly: false,
  disabled: false,
  loading: false,
  fullWidth: false,
});

const emit = defineEmits<{
  click: [event: MouseEvent];
}>();

const handleClick = (event: MouseEvent) => {
  if (!props.disabled && !props.loading) {
    emit('click', event);
  }
};
</script>

<style scoped>
.base-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
  text-decoration: none;
  min-width: 100px;
  position: relative;
}

.base-button:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.base-button.btn-full-width {
  width: 100%;
}

/* Sizes */
.base-button.btn-sm {
  padding: var(--spacing-xs) var(--spacing-md);
  font-size: var(--font-size-sm);
  min-width: 80px;
}

.base-button.btn-lg {
  padding: var(--spacing-md) var(--spacing-xl);
  font-size: var(--font-size-lg);
  min-width: 120px;
}

.base-button.btn-icon-only {
  min-width: auto;
  padding: var(--spacing-sm);
  aspect-ratio: 1;
}

.base-button.btn-sm.btn-icon-only {
  padding: var(--spacing-xs);
}

.base-button.btn-lg.btn-icon-only {
  padding: var(--spacing-md);
}

/* Variants */
.base-button.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.base-button.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.base-button.btn-secondary {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  color: var(--color-text-secondary);
}

.base-button.btn-secondary:hover:not(:disabled) {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
  color: var(--color-primary);
}

.base-button.btn-ghost {
  background: transparent;
  color: var(--color-text-secondary);
}

.base-button.btn-ghost:hover:not(:disabled) {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.base-button.btn-danger {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
}

.base-button.btn-danger:hover:not(:disabled) {
  background: var(--color-error);
  color: var(--color-text-primary);
}

.base-button.btn-success {
  background: var(--color-success-bg);
  color: var(--color-success);
  border: var(--border-width-thin) solid var(--color-success);
}

.base-button.btn-success:hover:not(:disabled) {
  background: var(--color-success);
  color: var(--color-text-primary);
}

/* Icon */
.btn-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.base-button.btn-sm .btn-icon {
  width: 16px;
  height: 16px;
}

.base-button.btn-lg .btn-icon {
  width: 24px;
  height: 24px;
}

.btn-icon.icon-left {
  order: -1;
}

.btn-icon.icon-right {
  order: 1;
}

.btn-label {
  flex: 1;
}

/* Loading state */
.btn-spinner {
  width: 16px;
  height: 16px;
  border: var(--border-width-medium) solid currentColor;
  opacity: 0.3;
  border-top-color: currentColor;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

.base-button.btn-sm .btn-spinner {
  width: 14px;
  height: 14px;
}

.base-button.btn-lg .btn-spinner {
  width: 20px;
  height: 20px;
}

.base-button.btn-loading {
  pointer-events: none;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
