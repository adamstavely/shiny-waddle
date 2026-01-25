<template>
  <form 
    class="base-form" 
    :class="formClass"
    @submit.prevent="handleSubmit"
  >
    <div v-if="title" class="form-header">
      <h2 v-if="title" class="form-title">{{ title }}</h2>
      <p v-if="description" class="form-description">{{ description }}</p>
    </div>

    <div class="form-body">
      <slot />
    </div>

    <div v-if="$slots.footer || showDefaultFooter" class="form-footer">
      <slot name="footer">
        <div v-if="showDefaultFooter" class="form-actions">
          <button 
            v-if="showCancel"
            type="button" 
            @click="handleCancel"
            class="btn-secondary"
          >
            {{ cancelLabel }}
          </button>
          <button 
            type="submit" 
            :disabled="disabled || loading"
            class="btn-primary"
          >
            <div v-if="loading" class="loading-spinner-small"></div>
            {{ submitLabel }}
          </button>
        </div>
      </slot>
    </div>
  </form>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface Props {
  title?: string;
  description?: string;
  submitLabel?: string;
  cancelLabel?: string;
  showCancel?: boolean;
  showDefaultFooter?: boolean;
  disabled?: boolean;
  loading?: boolean;
  variant?: 'default' | 'compact';
}

const props = withDefaults(defineProps<Props>(), {
  submitLabel: 'Submit',
  cancelLabel: 'Cancel',
  showCancel: true,
  showDefaultFooter: true,
  disabled: false,
  loading: false,
  variant: 'default',
});

const emit = defineEmits<{
  submit: [event: Event];
  cancel: [];
}>();

const formClass = computed(() => ({
  'form-compact': props.variant === 'compact',
}));

const handleSubmit = (event: Event) => {
  if (!props.disabled && !props.loading) {
    emit('submit', event);
  }
};

const handleCancel = () => {
  emit('cancel');
};
</script>

<style scoped>
.base-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.base-form.form-compact {
  gap: var(--spacing-md);
}

.form-header {
  margin-bottom: var(--spacing-sm);
}

.form-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.form-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.form-body {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.base-form.form-compact .form-body {
  gap: var(--spacing-md);
}

.form-footer {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.form-actions {
  display: flex;
  gap: var(--spacing-sm);
  justify-content: flex-end;
}

.btn-primary,
.btn-secondary {
  display: flex;
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
  min-width: 100px;
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  color: var(--color-text-secondary);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
  color: var(--color-primary);
}

.loading-spinner-small {
  width: 16px;
  height: 16px;
  border: var(--border-width-medium) solid var(--color-text-primary);
  opacity: 0.3;
  border-top-color: var(--color-text-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
