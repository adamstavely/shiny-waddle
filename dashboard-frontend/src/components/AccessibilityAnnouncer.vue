<template>
  <!-- Screen reader announcements -->
  <div
    ref="announcementContainer"
    class="sr-only"
    aria-live="polite"
    aria-atomic="true"
    role="status"
  ></div>
  <div
    ref="assertiveContainer"
    class="sr-only"
    aria-live="assertive"
    aria-atomic="true"
    role="alert"
  ></div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue';

const announcementContainer = ref<HTMLElement>();
const assertiveContainer = ref<HTMLElement>();

const handleAnnouncement = (event: CustomEvent) => {
  const { message, priority = 'polite' } = event.detail;
  const container = priority === 'assertive' ? assertiveContainer.value : announcementContainer.value;
  
  if (container) {
    container.textContent = '';
    // Force reflow
    void container.offsetHeight;
    container.textContent = message;
    
    // Clear after announcement
    setTimeout(() => {
      if (container) {
        container.textContent = '';
      }
    }, 1000);
  }
};

onMounted(() => {
  window.addEventListener('a11y-announce', handleAnnouncement as EventListener);
});

onBeforeUnmount(() => {
  window.removeEventListener('a11y-announce', handleAnnouncement as EventListener);
});
</script>

<style scoped>
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
</style>

