<template>
  <div class="app">
    <TopNav />
    <div class="app-layout">
      <Sidebar class="desktop-sidebar" />
      <MobileDrawer :is-open="drawerOpen" @close="closeDrawer" @navigate="handleNavigate" />
      <div class="content-wrapper">
        <Banner
          v-for="banner in activeBanners"
          :key="banner.id"
          :banner="banner"
          @dismiss="handleBannerDismiss"
        />
        <router-view />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import TopNav from './components/TopNav.vue';
import Sidebar from './components/Sidebar.vue';
import MobileDrawer from './components/MobileDrawer.vue';
import Banner, { type Banner as BannerType } from './components/Banner.vue';

const drawerOpen = ref(false);
const dismissedBanners = ref<Set<string>>(new Set());

// Mock banners - in real app, this would come from API/Admin
const banners = ref<BannerType[]>([
  {
    id: '1',
    message: 'System maintenance scheduled for this weekend. Some services may be unavailable.',
    type: 'warning',
    isActive: true,
    dismissible: true,
    linkUrl: 'https://status.example.com',
    linkText: 'View status page',
    priority: 10
  },
  {
    id: '2',
    message: 'New compliance policies have been updated. <strong>Review changes</strong> to ensure your applications remain compliant.',
    type: 'info',
    isActive: true,
    dismissible: true,
    linkUrl: '/policies',
    linkText: 'View policies',
    priority: 5
  }
]);

const activeBanners = computed(() => {
  return banners.value
    .filter(banner => banner.isActive && !dismissedBanners.value.has(banner.id))
    .sort((a, b) => (b.priority || 0) - (a.priority || 0));
});

const handleBannerDismiss = (bannerId: string) => {
  dismissedBanners.value.add(bannerId);
};

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
  position: relative;
}

.desktop-sidebar {
  display: none;
}

@media (min-width: 1024px) {
  .desktop-sidebar {
    display: block;
  }
  
  .content-wrapper {
    margin-left: 80px;
  }
}

.content-wrapper {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: hidden;
}

.content-wrapper > :deep(.banner) {
  margin: 0;
  border-radius: 0;
  flex-shrink: 0;
}

/* Ensure router-view content has proper padding and scrolling */
.content-wrapper > :deep(> *) {
  flex: 1;
  padding: 24px;
  overflow-y: auto;
  min-height: 0;
}
</style>

