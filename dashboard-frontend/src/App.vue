<template>
  <div class="app">
    <SkipLink />
    <AccessibilityAnnouncer />
    <TopNav />
    <div class="app-layout">
      <Sidebar class="desktop-sidebar" />
      <Drawer class="desktop-drawer" />
      <MobileDrawer :is-open="drawerOpen" @close="closeDrawer" @navigate="handleNavigate" />
      <main id="main-content" class="content-wrapper" :class="{ 'drawer-open': drawerIsOpen }" role="main" tabindex="-1">
        <Banner
          v-for="banner in activeBanners"
          :key="banner.id"
          :banner="banner"
          @dismiss="handleBannerDismiss"
        />
        <router-view :key="route.fullPath" />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { useRoute } from 'vue-router';
import TopNav from './components/TopNav.vue';
import Sidebar from './components/Sidebar.vue';
import Drawer from './components/Drawer.vue';
import MobileDrawer from './components/MobileDrawer.vue';
import Banner, { type Banner as BannerType } from './components/Banner.vue';
import SkipLink from './components/SkipLink.vue';
import AccessibilityAnnouncer from './components/AccessibilityAnnouncer.vue';

const route = useRoute();

const drawerOpen = ref(false);
const drawerIsOpen = ref(false);

// Load dismissed banners from localStorage
const loadDismissedBanners = (): Set<string> => {
  try {
    const stored = localStorage.getItem('dismissedBanners');
    if (stored) {
      return new Set(JSON.parse(stored));
    }
  } catch (e) {
    console.error('Failed to load dismissed banners from localStorage', e);
  }
  return new Set<string>();
};

const dismissedBanners = ref<Set<string>>(loadDismissedBanners());

// Save dismissed banners to localStorage
const saveDismissedBanners = (bannerIds: Set<string>) => {
  try {
    localStorage.setItem('dismissedBanners', JSON.stringify(Array.from(bannerIds)));
  } catch (e) {
    console.error('Failed to save dismissed banners to localStorage', e);
  }
};

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
  saveDismissedBanners(dismissedBanners.value);
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

const handleDrawerStateChange = (event: CustomEvent) => {
  drawerIsOpen.value = event.detail.isOpen;
};

onMounted(() => {
  // Listen for drawer toggle (mobile)
  window.addEventListener('toggle-drawer', handleToggleDrawer as EventListener);
  // Listen for drawer state changes (desktop)
  window.addEventListener('drawer-state-change', handleDrawerStateChange as EventListener);
});

onBeforeUnmount(() => {
  window.removeEventListener('toggle-drawer', handleToggleDrawer as EventListener);
  window.removeEventListener('drawer-state-change', handleDrawerStateChange as EventListener);
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

.desktop-drawer {
  display: none;
}

/* Tablet styles */
@media (min-width: 768px) and (max-width: 1023px) {
  .desktop-sidebar {
    display: block;
  }
  
  .desktop-drawer {
    display: none; /* Hide drawer on tablet for more space */
  }
  
  .content-wrapper {
    margin-left: 80px;
    transition: margin-left 0.3s ease;
  }
  
  .content-wrapper.drawer-open {
    margin-left: 80px; /* No drawer on tablet */
  }
}

/* Desktop styles */
@media (min-width: 1024px) {
  .desktop-sidebar {
    display: block;
  }
  
  .desktop-drawer {
    display: block;
  }
  
  .content-wrapper {
    margin-left: 80px; /* Only sidebar width, drawer is collapsible */
    transition: margin-left 0.3s ease;
  }
  
  .content-wrapper.drawer-open {
    margin-left: 340px !important; /* 80px sidebar + 240px drawer + 20px gap */
  }
  
  /* When drawer is collapsed, ensure toggle button is still visible */
  .desktop-drawer.drawer-collapsed {
    width: 0;
    overflow: visible;
  }
  
  .desktop-drawer.drawer-collapsed .drawer-toggle {
    position: fixed;
    left: 88px; /* 80px sidebar + 8px offset */
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

/* Responsive padding for content */
@media (max-width: 767px) {
  .content-wrapper > :deep(> *) {
    padding: 16px;
  }
}

@media (min-width: 768px) and (max-width: 1023px) {
  .content-wrapper > :deep(> *) {
    padding: 20px;
  }
}

/* Prevent scrolling on home page */
.content-wrapper > :deep(.home) {
  overflow: hidden;
  padding: 0;
}
</style>

