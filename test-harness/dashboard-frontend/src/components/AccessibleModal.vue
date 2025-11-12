<template>
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="isOpen"
        class="modal-overlay"
        @click="handleOverlayClick"
        role="dialog"
        :aria-modal="true"
        :aria-labelledby="titleId"
        :aria-describedby="descriptionId"
      >
        <div
          class="modal-content"
          @click.stop
          ref="modalRef"
          role="document"
        >
          <div class="modal-header">
            <h2 :id="titleId" class="modal-title">{{ title }}</h2>
            <button
              @click="close"
              class="modal-close"
              aria-label="Close dialog"
              type="button"
            >
              <X class="close-icon" aria-hidden="true" />
            </button>
          </div>
          
          <div :id="descriptionId" class="modal-body">
            <slot />
          </div>
          
          <div v-if="$slots.footer" class="modal-footer">
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount } from 'vue';
import { X } from 'lucide-vue-next';
import { trapFocus, restoreFocus } from '../utils/accessibility';
import { generateId } from '../utils/accessibility';

interface Props {
  isOpen: boolean;
  title: string;
  description?: string;
  closeOnOverlayClick?: boolean;
  closeOnEscape?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  closeOnOverlayClick: true,
  closeOnEscape: true,
  description: '',
});

const emit = defineEmits<{
  close: [];
}>();

const modalRef = ref<HTMLElement>();
const titleId = generateId('modal-title');
const descriptionId = generateId('modal-description');
let previousActiveElement: HTMLElement | null = null;
let cleanupFocusTrap: (() => void) | null = null;

const close = () => {
  emit('close');
};

const handleOverlayClick = () => {
  if (props.closeOnOverlayClick) {
    close();
  }
};

const handleEscape = (e: KeyboardEvent) => {
  if (props.isOpen && props.closeOnEscape && e.key === 'Escape') {
    close();
  }
};

watch(() => props.isOpen, (isOpen) => {
  if (isOpen) {
    // Store previous focus
    previousActiveElement = document.activeElement as HTMLElement;
    
    // Trap focus in modal
    if (modalRef.value) {
      cleanupFocusTrap = trapFocus(modalRef.value);
    }
    
    // Prevent body scroll
    document.body.style.overflow = 'hidden';
    
    // Add escape handler
    document.addEventListener('keydown', handleEscape);
  } else {
    // Restore focus
    if (previousActiveElement) {
      restoreFocus(previousActiveElement);
    }
    
    // Cleanup focus trap
    if (cleanupFocusTrap) {
      cleanupFocusTrap();
      cleanupFocusTrap = null;
    }
    
    // Restore body scroll
    document.body.style.overflow = '';
    
    // Remove escape handler
    document.removeEventListener('keydown', handleEscape);
  }
});

onBeforeUnmount(() => {
  if (cleanupFocusTrap) {
    cleanupFocusTrap();
  }
  document.removeEventListener('keydown', handleEscape);
  document.body.style.overflow = '';
});
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 24px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  max-width: 90vw;
  max-height: 90vh;
  width: 100%;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  outline: none;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
  min-width: 44px;
  min-height: 44px;
}

.modal-close:hover,
.modal-close:focus {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  outline: 3px solid #4facfe;
  outline-offset: 2px;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
  overflow-y: auto;
  flex: 1;
}

.modal-footer {
  padding: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

/* Transitions */
.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.2s;
}

.modal-enter-active .modal-content,
.modal-leave-active .modal-content {
  transition: transform 0.2s, opacity 0.2s;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-from .modal-content,
.modal-leave-to .modal-content {
  transform: scale(0.95);
  opacity: 0;
}
</style>

