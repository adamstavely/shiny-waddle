<template>
  <Teleport to="body">
    <!-- Backdrop -->
    <Transition name="fade">
      <div
        v-if="isOpen"
        class="drawer-backdrop"
        @click="close"
        aria-hidden="true"
      ></div>
    </Transition>

    <!-- Drawer -->
    <Transition name="slide">
      <aside
        v-if="isOpen"
        class="mobile-drawer"
        role="navigation"
        aria-label="Mobile navigation"
      >
        <div class="drawer-header">
          <div class="drawer-logo">
            <Shield class="logo-icon" />
            <span class="logo-text">Sentinel</span>
          </div>
          <button
            @click="close"
            class="close-button"
            aria-label="Close navigation"
          >
            <X class="close-icon" />
          </button>
        </div>

        <nav class="drawer-nav">
          <a
            v-for="item in menuItems"
            :key="item.path"
            :href="item.path"
            @click.prevent="handleNavClick(item.path)"
            :class="[
              'drawer-nav-item',
              isActive(item.path) ? 'drawer-nav-item-active' : ''
            ]"
          >
            <component :is="item.icon" class="drawer-nav-icon" />
            <span>{{ item.label }}</span>
          </a>
        </nav>

        <div class="drawer-footer">
          <button
            @click="handleSettingsClick"
            class="drawer-nav-item"
          >
            <Settings class="drawer-nav-icon" />
            <span>Settings</span>
          </button>
        </div>
      </aside>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute } from 'vue-router';
import { 
  LayoutDashboard, 
  Shield, 
  FileText, 
  TestTube, 
  BarChart3, 
  AlertTriangle,
  Settings,
  History,
  X
} from 'lucide-vue-next';

const props = defineProps<{
  isOpen: boolean;
}>();

const emit = defineEmits<{
  close: [];
  navigate: [path: string];
}>();

const route = useRoute();
const currentPath = ref(route.path);

const menuItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/tests', label: 'Tests', icon: TestTube },
  { path: '/reports', label: 'Reports', icon: FileText },
  { path: '/policies', label: 'Policies', icon: Shield },
  { path: '/analytics', label: 'Analytics', icon: BarChart3 },
  { path: '/violations', label: 'Violations', icon: AlertTriangle },
  { path: '/history', label: 'History', icon: History },
  { path: '/admin', label: 'Admin', icon: Settings },
];

const isActive = (path: string): boolean => {
  if (path === '/dashboard') {
    return currentPath.value === '/dashboard';
  }
  return currentPath.value === path || currentPath.value.startsWith(path + '/');
};

const close = () => {
  emit('close');
};

const handleNavClick = (path: string) => {
  window.location.href = path;
  close();
};

// Watch for route changes to update active state
watch(() => route.path, (newPath) => {
  currentPath.value = newPath;
});

const handleSettingsClick = () => {
  window.location.href = '/settings';
  close();
};
</script>


<style scoped>
.drawer-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  z-index: 100;
  backdrop-filter: blur(4px);
}

.mobile-drawer {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  width: 280px;
  max-width: 85vw;
  background: linear-gradient(180deg, #1a1f2e 0%, #0f1419 100%);
  border-right: 1px solid rgba(79, 172, 254, 0.2);
  z-index: 101;
  display: flex;
  flex-direction: column;
  box-shadow: 4px 0 24px rgba(0, 0, 0, 0.5);
}

.drawer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.drawer-logo {
  display: flex;
  align-items: center;
  gap: 12px;
}

.drawer-logo .logo-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
  stroke-width: 2;
}

.drawer-logo .logo-text {
  font-size: 1.25rem;
  font-weight: 700;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.close-button {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  padding: 0;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
}

.close-button:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.drawer-nav {
  flex: 1;
  overflow-y: auto;
  padding: 16px 0;
}

.drawer-nav-item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 14px 20px;
  color: #a0aec0;
  text-decoration: none;
  transition: all 0.2s;
  border-left: 3px solid transparent;
}

.drawer-nav-item:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.drawer-nav-item-active {
  background: rgba(79, 172, 254, 0.15);
  color: #4facfe;
  border-left-color: #4facfe;
}

.drawer-nav-icon {
  width: 20px;
  height: 20px;
  stroke-width: 2;
  flex-shrink: 0;
}

.drawer-footer {
  padding: 16px 0;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.slide-enter-active,
.slide-leave-active {
  transition: transform 0.3s ease;
}

.slide-enter-from,
.slide-leave-to {
  transform: translateX(-100%);
}
</style>

