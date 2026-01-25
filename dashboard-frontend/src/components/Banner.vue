<template>
  <Transition name="banner">
    <div
      v-if="banner && banner.isActive"
      class="banner"
      :class="`banner-${banner.type}`"
    >
      <div class="banner-content">
        <component v-if="banner.icon" :is="banner.icon" class="banner-icon" />
        <div class="banner-text">
          <p class="banner-message" v-html="banner.message"></p>
          <a
            v-if="banner.linkUrl && banner.linkText"
            :href="banner.linkUrl"
            class="banner-link"
            target="_blank"
            rel="noopener noreferrer"
          >
            {{ banner.linkText }}
            <ExternalLink class="link-icon" />
          </a>
        </div>
        <button
          v-if="banner.dismissible"
          @click="dismiss"
          class="banner-close"
          aria-label="Dismiss banner"
        >
          <X class="close-icon" />
        </button>
      </div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { X, ExternalLink } from 'lucide-vue-next';

export interface Banner {
  id: string;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success';
  isActive: boolean;
  dismissible: boolean;
  linkUrl?: string;
  linkText?: string;
  icon?: any;
  priority?: number;
}

const props = defineProps<{
  banner: Banner | null;
}>();

const emit = defineEmits<{
  dismiss: [bannerId: string];
}>();

const dismiss = () => {
  if (props.banner) {
    emit('dismiss', props.banner.id);
  }
};
</script>

<style scoped>
.banner {
  width: 100%;
  padding: 12px 24px;
  border-bottom: 1px solid;
  z-index: 10;
  flex-shrink: 0;
}

.banner-info {
  background: rgba(79, 172, 254, 0.1);
  border-bottom-color: rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.banner-warning {
  background: rgba(251, 191, 36, 0.1);
  border-bottom-color: rgba(251, 191, 36, 0.3);
  color: #fbbf24;
}

.banner-error {
  background: rgba(252, 129, 129, 0.1);
  border-bottom-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.banner-success {
  background: rgba(34, 197, 94, 0.1);
  border-bottom-color: rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.banner-content {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  gap: 12px;
}

.banner-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.banner-text {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.banner-message {
  margin: 0;
  font-size: 0.9rem;
  font-weight: 500;
  line-height: 1.5;
}

.banner-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: inherit;
  text-decoration: underline;
  font-weight: 600;
  transition: opacity 0.2s;
}

.banner-link:hover {
  opacity: 0.8;
}

.link-icon {
  width: 14px;
  height: 14px;
}

.banner-close {
  padding: 4px;
  background: transparent;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  color: inherit;
  opacity: 0.7;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.banner-close:hover {
  opacity: 1;
  background: rgba(255, 255, 255, 0.1);
}

.close-icon {
  width: 18px;
  height: 18px;
}

.banner-enter-active,
.banner-leave-active {
  transition: all 0.3s ease;
}

.banner-enter-from,
.banner-leave-to {
  opacity: 0;
  transform: translateY(-100%);
}
</style>

