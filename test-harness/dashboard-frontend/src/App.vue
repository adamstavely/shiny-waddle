<template>
  <div class="app">
    <TopNav />
    <div class="app-layout">
      <Sidebar class="desktop-sidebar" />
      <MobileDrawer :is-open="drawerOpen" @close="closeDrawer" @navigate="handleNavigate" />
      <div class="content-wrapper">
        <router-view />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue';
import TopNav from './components/TopNav.vue';
import Sidebar from './components/Sidebar.vue';
import MobileDrawer from './components/MobileDrawer.vue';

const drawerOpen = ref(false);

const closeDrawer = () => {
  drawerOpen.value = false;
};

const handleNavigate = (path: string) => {
  // Router will handle navigation
  window.location.href = path;
};

const handleToggleDrawer = (event: CustomEvent) => {
  drawerOpen.value = event.detail.open;
};

onMounted(() => {
  // Listen for drawer toggle
  window.addEventListener('toggle-drawer', handleToggleDrawer as EventListener);
});

onBeforeUnmount(() => {
  window.removeEventListener('toggle-drawer', handleToggleDrawer as EventListener);
});
</script>

<style scoped>
.app {
  min-height: 100vh;
  background: linear-gradient(135deg, #0f1419 0%, #1a2332 50%, #0f1419 100%);
  display: flex;
  flex-direction: column;
}

.app-layout {
  display: flex;
  flex: 1;
  min-height: 0;
}

.desktop-sidebar {
  display: none;
}

@media (min-width: 1024px) {
  .desktop-sidebar {
    display: block;
  }
}

.content-wrapper {
  flex: 1;
  padding: 24px;
  overflow-y: auto;
  min-width: 0;
}
</style>

