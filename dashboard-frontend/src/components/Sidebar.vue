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
            v-if="item.path !== '/policies/exceptions'"
            :to="item.path === '/test-design-library' ? '/tests' : item.path"
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
      <router-link
        to="/admin"
        :class="[
          'nav-item',
          isActive('/admin') ? 'nav-item-active' : ''
        ]"
        title="Admin"
      >
        <component :is="UserCog" class="nav-icon" />
        <span class="nav-label">Admin</span>
      </router-link>
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
  PlayCircle,
  Target,
  AlertTriangle,
  CheckCircle
} from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();
const currentPath = ref(route.path);

const menuItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, divider: false },
  { path: '/targets', label: 'Targets', icon: Target, divider: false },
  { path: '/test-design-library', label: 'Tests', icon: BookOpen, divider: false },
  { path: '/policies', label: 'Access Control', icon: FileText, divider: false },
  { path: '/policies/exceptions', label: 'Exceptions', icon: AlertTriangle, divider: false },
  { path: '/validators', label: 'Validators', icon: CheckCircle, divider: false },
];

// Test Design Library pages
const testDesignLibraryPages = [
  '/tests',
  '/tests/batteries', '/tests/harnesses', '/tests/suites',
  '/tests/individual', '/tests/findings',
  '/tests/history', '/tests/agent-tests'
];

// Policies & Config pages
const policiesConfigPages = [
  '/policies',
  '/resources',
  '/configuration-validation',
  '/salesforce-experience-cloud'
];

// Exceptions is a top-level page
const exceptionsPages = [
  '/policies/exceptions'
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

// Targets pages (includes targets overview, applications, and platform instances)
const targetsPages = [
  '/targets',
  '/applications',
  '/applications/platform-instances'
];

const isActive = (path: string): boolean => {
  if (path === '/dashboard') {
    return currentPath.value === '/dashboard' || currentPath.value === '/';
  }
  if (path === '/targets') {
    return targetsPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/test-design-library') {
    // Map to /tests overview page
    return currentPath.value === '/tests' || testDesignLibraryPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/policies') {
    return policiesConfigPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/policies/exceptions') {
    return exceptionsPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/validators') {
    return currentPath.value === '/validators' || currentPath.value.startsWith('/validators/');
  }
  if (path === '/admin') {
    return currentPath.value === '/admin' || currentPath.value.startsWith('/admin/');
  }
  return currentPath.value === path || currentPath.value.startsWith(path + '/');
};

const handleNavClick = (path: string) => {
  // Only handle exceptions as a special case (if needed)
  // All other items now navigate directly to their overview pages
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
  top: calc(var(--spacing-2xl) + var(--spacing-md)); /* 64px - matches TopNav height */
  left: 0;
  height: calc(100vh - calc(var(--spacing-2xl) + var(--spacing-md)));
  width: calc(var(--spacing-2xl) + var(--spacing-xl)); /* 80px */
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
  gap: var(--spacing-xs);
  min-height: 0;
  padding-bottom: var(--spacing-2xl); /* Space for admin section */
}

.nav-items-container {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.nav-admin-section {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  background: linear-gradient(180deg, transparent 0%, var(--color-bg-primary) 20%);
  padding-top: var(--spacing-sm);
  padding-bottom: var(--spacing-md);
  z-index: 10;
}

.nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-sm) var(--spacing-sm);
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
  background: var(--color-info-bg);
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
  width: var(--spacing-lg);
  height: var(--spacing-lg);
  margin-bottom: var(--spacing-xs);
  stroke-width: 2;
}

.nav-label {
  font-size: var(--font-size-xs);
  font-weight: 500;
  text-align: center;
  line-height: 1.2;
}

.nav-divider {
  height: var(--border-width-thin);
  margin: var(--spacing-sm) var(--spacing-md);
  background: var(--border-color-muted);
}

/* Scrollbar styling */
.sidebar-nav::-webkit-scrollbar {
  width: var(--spacing-xs);
}

.sidebar-nav::-webkit-scrollbar-track {
  background: transparent;
}

.sidebar-nav::-webkit-scrollbar-thumb {
  background: var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-xs);
}

.sidebar-nav::-webkit-scrollbar-thumb:hover {
  background: var(--border-color-primary);
  opacity: 0.5;
}
</style>

