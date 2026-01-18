<template>
  <aside 
    class="sidebar"
    aria-label="Main navigation"
  >
    <!-- Navigation Items -->
    <nav class="sidebar-nav" role="navigation">
      <div class="nav-items-container">
        <template v-for="(item, index) in menuItems" :key="item.path">
          <router-link
            v-if="!['/test-design-library', '/admin', '/policies'].includes(item.path)"
            :to="item.path"
            :class="[
              'nav-item',
              isActive(item.path) ? 'nav-item-active' : ''
            ]"
            :title="item.label"
          >
            <component :is="item.icon" class="nav-icon" />
            <span class="nav-label">{{ item.label }}</span>
          </router-link>
          <button
            v-else
            @click="handleNavClick(item.path)"
            :class="[
              'nav-item',
              isActive(item.path) ? 'nav-item-active' : ''
            ]"
            :title="item.label"
          >
            <component :is="item.icon" class="nav-icon" />
            <span class="nav-label">{{ item.label }}</span>
          </button>
          <!-- Divider after certain items -->
          <div 
            v-if="item.divider"
            class="nav-divider"
            aria-hidden="true"
          ></div>
        </template>
      </div>
    </nav>
    
    <!-- Admin Item - Pinned at Bottom -->
    <div class="nav-admin-section">
      <div class="nav-divider" aria-hidden="true"></div>
      <button
        @click="handleNavClick('/admin')"
        :class="[
          'nav-item',
          isActive('/admin') ? 'nav-item-active' : ''
        ]"
        title="Admin"
      >
        <component :is="UserCog" class="nav-icon" />
        <span class="nav-label">Admin</span>
      </button>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { 
  LayoutDashboard, 
  Shield, 
  FileText, 
  TestTube, 
  BarChart3, 
  Settings,
  Globe,
  Database,
  Cloud,
  Lock,
  Plug,
  GitBranch,
  Users,
  Folder,
  FileCheck,
  CheckCircle2,
  UserCog,
  KeyRound,
  BookOpen,
  PlayCircle
} from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();
const currentPath = ref(route.path);

const menuItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, divider: false },
  { path: '/applications', label: 'Applications', icon: Database, divider: false },
  { path: '/test-design-library', label: 'Test Design Library', icon: BookOpen, divider: false },
  { path: '/policies', label: 'Policies & Config', icon: Shield, divider: false },
  { path: '/insights', label: 'Insights & Reports', icon: BarChart3, divider: false },
];

// Test Design Library pages
const testDesignLibraryPages = [
  '/tests',
  '/tests/batteries', '/tests/harnesses', '/tests/suites',
  '/tests/individual', '/tests/library', '/tests/findings',
  '/tests/history'
];

// Policies & Config pages
const policiesConfigPages = [
  '/policies',
  '/resources',
  '/configuration-validation',
  '/environment-config-testing',
  '/salesforce-experience-cloud'
];

// Insights & Reports pages
const insightsReportsPages = [
  '/insights',
  '/insights/overview',
  '/insights/analytics',
  '/insights/predictions',
  '/insights/runs',
  '/insights/reports',
  '/insights/trends',
];

const isActive = (path: string): boolean => {
  if (path === '/dashboard') {
    return currentPath.value === '/dashboard' || currentPath.value === '/';
  }
  if (path === '/applications') {
    return currentPath.value === '/applications' || currentPath.value.startsWith('/applications/');
  }
  if (path === '/test-design-library') {
    return testDesignLibraryPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/policies') {
    return policiesConfigPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/insights') {
    return insightsReportsPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/admin') {
    return currentPath.value === '/admin' || currentPath.value.startsWith('/admin/');
  }
  return currentPath.value === path || currentPath.value.startsWith(path + '/');
};

const handleNavClick = (path: string) => {
  // For drawer items, open the drawer with that category's content
  if (path === '/test-design-library') {
    // Emit event to open drawer with test-design-library category
    window.dispatchEvent(new CustomEvent('open-drawer', { detail: { category: 'test-design-library' } }));
    return;
  }
  if (path === '/policies') {
    // Emit event to open drawer with policies-config category
    window.dispatchEvent(new CustomEvent('open-drawer', { detail: { category: 'policies-config' } }));
    return;
  }
  if (path === '/admin') {
    // Emit event to open drawer with admin category
    window.dispatchEvent(new CustomEvent('open-drawer', { detail: { category: 'admin' } }));
    return;
  }
  // Use Vue Router for navigation (including /insights - it navigates directly)
  router.push(path);
};

// Watch for route changes to update active state
watch(() => route.path, (newPath) => {
  currentPath.value = newPath;
});
</script>

<style scoped>
.sidebar {
  position: fixed;
  top: 64px;
  left: 0;
  height: calc(100vh - 64px);
  width: 80px;
  background: linear-gradient(180deg, var(--color-bg-secondary) 0%, var(--color-bg-primary) 100%);
  border-right: var(--border-width-thin) solid var(--border-color-primary);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  z-index: 30;
  overflow: hidden;
}

.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 16px 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-height: 0;
  padding-bottom: 80px; /* Space for admin section */
}

.nav-items-container {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.nav-admin-section {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  background: linear-gradient(180deg, transparent 0%, var(--color-bg-primary) 20%);
  padding-top: 8px;
  padding-bottom: 16px;
  z-index: 10;
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
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  cursor: pointer;
  border: var(--border-width-thin) solid transparent;
  position: relative;
  background: transparent;
  font-family: inherit;
  font-size: inherit;
}

.nav-item:hover {
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-color: var(--border-color-primary);
}

.nav-item-active {
  background: rgba(79, 172, 254, 0.15);
  border-color: var(--border-color-secondary);
  color: var(--color-primary);
}

.nav-item-active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 60%;
  background: var(--gradient-primary);
  border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0;
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

