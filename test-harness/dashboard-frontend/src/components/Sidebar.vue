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
            v-if="!['/tests', '/access-control', '/platform-config', '/data-security', '/insights', '/admin'].includes(item.path)"
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
  KeyRound
} from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();
const currentPath = ref(route.path);

const menuItems = [
  { path: '/insights', label: 'Insights', icon: LayoutDashboard, divider: false },
  { path: '/tests', label: 'Tests', icon: TestTube, divider: false },
  { path: '/access-control', label: 'Access Control', icon: Shield, divider: false },
  { path: '/platform-config', label: 'Platform Config', icon: Settings, divider: false },
  { path: '/data-security', label: 'Data Security', icon: Database, divider: true },
];

// Test pages
const testPages = [
  '/policy-validation',
  '/api-security', '/users', '/api-gateway', '/dlp',
  '/distributed-systems', '/network-policies',
  '/rls-cls'
];

// Access Control pages
const accessControlPages = [
  '/policies', '/resources', '/tests/user-simulation',
  '/tests/policy-validation', '/policy-validation'
];

// Platform Config pages
const platformConfigPages = [
  '/configuration-validation'
];

// Data Security pages
const dataSecurityPages = [
  '/datasets', '/contracts'
];

const isActive = (path: string): boolean => {
  if (path === '/insights') {
    return currentPath.value === '/insights' || currentPath.value.startsWith('/insights');
  }
  if (path === '/tests') {
    return currentPath.value === '/tests' || currentPath.value.startsWith('/tests/') ||
           testPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/access-control') {
    return accessControlPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/platform-config') {
    return platformConfigPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/data-security') {
    return dataSecurityPages.some(page => currentPath.value === page || currentPath.value.startsWith(page + '/'));
  }
  if (path === '/admin') {
    return currentPath.value === '/admin' || currentPath.value.startsWith('/admin/');
  }
  return currentPath.value === path || currentPath.value.startsWith(path + '/');
};

const handleNavClick = (path: string) => {
  // For drawer items, open the drawer with that category's content
  if (['/tests', '/access-control', '/platform-config', '/data-security', '/insights', '/admin'].includes(path)) {
    // Emit event to open drawer with specific category
    window.dispatchEvent(new CustomEvent('open-drawer', { detail: { category: path.replace('/', '') } }));
    return;
  }
  // Use Vue Router for navigation
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
  background: linear-gradient(180deg, #1a1f2e 0%, #0f1419 100%);
  border-right: 1px solid rgba(79, 172, 254, 0.2);
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
  background: linear-gradient(180deg, transparent 0%, #0f1419 20%);
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
  color: #a0aec0;
  transition: all 0.2s;
  cursor: pointer;
  border: 1px solid transparent;
  position: relative;
  background: transparent;
  font-family: inherit;
  font-size: inherit;
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

