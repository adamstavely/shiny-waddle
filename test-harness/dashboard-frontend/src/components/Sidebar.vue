<template>
  <aside 
    class="sidebar"
    aria-label="Main navigation"
  >
    <!-- Navigation Items -->
    <nav class="sidebar-nav" role="navigation">
      <template v-for="(item, index) in menuItems" :key="item.path">
        <a
          :href="item.path"
          @click.prevent="handleNavClick(item.path)"
          :class="[
            'nav-item',
            isActive(item.path) ? 'nav-item-active' : ''
          ]"
          :title="item.label"
        >
          <component :is="item.icon" class="nav-icon" />
          <span class="nav-label">{{ item.label }}</span>
        </a>
        <!-- Divider after certain items -->
        <div 
          v-if="item.divider"
          class="nav-divider"
          aria-hidden="true"
        ></div>
      </template>
    </nav>
  </aside>
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
  History
} from 'lucide-vue-next';

const route = useRoute();
const currentPath = ref(route.path);

const menuItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/tests', label: 'Tests', icon: TestTube, divider: false },
  { path: '/reports', label: 'Reports', icon: FileText, divider: false },
  { path: '/policies', label: 'Policies', icon: Shield, divider: true },
  { path: '/analytics', label: 'Analytics', icon: BarChart3, divider: false },
  { path: '/violations', label: 'Violations', icon: AlertTriangle, divider: false },
  { path: '/history', label: 'History', icon: History, divider: false },
];

const isActive = (path: string): boolean => {
  if (path === '/dashboard') {
    return currentPath.value === '/dashboard';
  }
  return currentPath.value === path || currentPath.value.startsWith(path + '/');
};

const handleNavClick = (path: string) => {
  // Router will handle navigation
  window.location.href = path;
};

// Watch for route changes to update active state
watch(() => route.path, (newPath) => {
  currentPath.value = newPath;
});
</script>

<style scoped>
.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  width: 80px;
  background: linear-gradient(180deg, #1a1f2e 0%, #0f1419 100%);
  border-right: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  z-index: 30;
  overflow-y: auto;
  overflow-x: hidden;
}

.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 16px 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 12px 8px;
  margin: 0 8px;
  border-radius: 8px;
  text-decoration: none;
  color: #a0aec0;
  transition: all 0.2s;
  cursor: pointer;
  border: 1px solid transparent;
  position: relative;
}

.nav-item:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border-color: rgba(79, 172, 254, 0.2);
}

.nav-item-active {
  background: rgba(79, 172, 254, 0.15);
  border-color: rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.nav-item-active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 60%;
  background: linear-gradient(180deg, #4facfe 0%, #00f2fe 100%);
  border-radius: 0 2px 2px 0;
}

.nav-icon {
  width: 24px;
  height: 24px;
  margin-bottom: 6px;
  stroke-width: 2;
}

.nav-label {
  font-size: 0.7rem;
  font-weight: 500;
  text-align: center;
  line-height: 1.2;
}

.nav-divider {
  height: 1px;
  margin: 8px 16px;
  background: rgba(79, 172, 254, 0.1);
}

/* Scrollbar styling */
.sidebar-nav::-webkit-scrollbar {
  width: 4px;
}

.sidebar-nav::-webkit-scrollbar-track {
  background: transparent;
}

.sidebar-nav::-webkit-scrollbar-thumb {
  background: rgba(79, 172, 254, 0.3);
  border-radius: 2px;
}

.sidebar-nav::-webkit-scrollbar-thumb:hover {
  background: rgba(79, 172, 254, 0.5);
}
</style>

