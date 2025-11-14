<template>
  <aside 
    class="drawer"
    :class="{ 'drawer-collapsed': isCollapsed }"
    aria-label="Category navigation"
  >
    <button 
      @click="toggleDrawer" 
      class="drawer-toggle"
      :aria-label="isCollapsed ? 'Expand drawer' : 'Collapse drawer'"
      :aria-expanded="!isCollapsed"
    >
      <component 
        :is="isCollapsed ? Menu : ChevronLeft" 
        class="toggle-icon" 
        aria-hidden="true"
      />
    </button>
    <nav class="drawer-nav" role="navigation" v-show="!isCollapsed && activeCategory">
      <!-- Tests Category -->
      <div v-if="activeCategory === 'tests'" class="drawer-category" data-category="tests">
        <!-- Main Tests Pages -->
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/tests"
            @click.prevent="handleNavClick('/tests')"
            :class="['drawer-item', isActive('/tests') ? 'drawer-item-active' : '']"
          >
            <LayoutDashboard class="item-icon" />
            <span>Overview</span>
          </a>
          <a
            href="/tests/batteries"
            @click.prevent="handleNavClick('/tests/batteries')"
            :class="['drawer-item', isActive('/tests/batteries') ? 'drawer-item-active' : '']"
          >
            <Battery class="item-icon" />
            <span>Test Batteries</span>
          </a>
          <a
            href="/tests/harnesses"
            @click.prevent="handleNavClick('/tests/harnesses')"
            :class="['drawer-item', isActive('/tests/harnesses') ? 'drawer-item-active' : '']"
          >
            <Layers class="item-icon" />
            <span>Test Harnesses</span>
          </a>
          <a
            href="/tests/suites"
            @click.prevent="handleNavClick('/tests/suites')"
            :class="['drawer-item', isActive('/tests/suites') ? 'drawer-item-active' : '']"
          >
            <List class="item-icon" />
            <span>Test Suites</span>
          </a>
          <a
            href="/tests/library"
            @click.prevent="handleNavClick('/tests/library')"
            :class="['drawer-item', isActive('/tests/library') ? 'drawer-item-active' : '']"
          >
            <BookOpen class="item-icon" />
            <span>Test Library</span>
          </a>
          <a
            href="/tests/findings"
            @click.prevent="handleNavClick('/tests/findings')"
            :class="['drawer-item', isActive('/tests/findings') ? 'drawer-item-active' : '']"
          >
            <AlertCircle class="item-icon" />
            <span>Findings</span>
          </a>
        </div>

        <!-- Separator -->
        <div style="height: 1px; background: rgba(79, 172, 254, 0.2); margin: 16px 20px;"></div>

        <!-- Test Tools -->
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/tests/configurations"
            @click.prevent="handleNavClick('/tests/configurations')"
            :class="['drawer-item', isActive('/tests/configurations') || isActive('/test-configurations') ? 'drawer-item-active' : '']"
          >
            <Settings class="item-icon" />
            <span>Test Configurations</span>
          </a>
        </div>
      </div>

      <!-- Access Control Category -->
      <div v-if="activeCategory === 'access-control'" class="drawer-category" data-category="access-control">
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/policies"
            @click.prevent="handleNavClick('/policies')"
            :class="['drawer-item', isActive('/policies') ? 'drawer-item-active' : '']"
          >
            <Shield class="item-icon" />
            <span>Policies</span>
          </a>
          <a
            href="/resources"
            @click.prevent="handleNavClick('/resources')"
            :class="['drawer-item', isActive('/resources') ? 'drawer-item-active' : '']"
          >
            <Folder class="item-icon" />
            <span>Resources</span>
          </a>
          <a
            href="/tests/user-simulation"
            @click.prevent="handleNavClick('/tests/user-simulation')"
            :class="['drawer-item', isActive('/tests/user-simulation') || isActive('/users') ? 'drawer-item-active' : '']"
          >
            <Users class="item-icon" />
            <span>User Simulation</span>
          </a>
          <a
            href="/tests/policy-validation"
            @click.prevent="handleNavClick('/tests/policy-validation')"
            :class="['drawer-item', isActive('/tests/policy-validation') || isActive('/policy-validation') ? 'drawer-item-active' : '']"
          >
            <FileSearch class="item-icon" />
            <span>Policy Validation</span>
          </a>
        </div>
      </div>

      <!-- Platform Config Category -->
      <div v-if="activeCategory === 'platform-config'" class="drawer-category" data-category="platform-config">
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/configuration-validation"
            @click.prevent="handleNavClick('/configuration-validation')"
            :class="['drawer-item', isActive('/configuration-validation') ? 'drawer-item-active' : '']"
          >
            <Shield class="item-icon" />
            <span>Config Validator</span>
          </a>
        </div>
      </div>

      <!-- Data Security Category -->
      <div v-if="activeCategory === 'data-security'" class="drawer-category" data-category="data-security">
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/datasets"
            @click.prevent="handleNavClick('/datasets')"
            :class="['drawer-item', isActive('/datasets') ? 'drawer-item-active' : '']"
          >
            <Database class="item-icon" />
            <span>Datasets</span>
          </a>
          <a
            href="/contracts"
            @click.prevent="handleNavClick('/contracts')"
            :class="['drawer-item', isActive('/contracts') ? 'drawer-item-active' : '']"
          >
            <FileCheck class="item-icon" />
            <span>Contracts</span>
          </a>
        </div>
      </div>

      <!-- Insights Category -->
      <div v-if="activeCategory === 'insights'" class="drawer-category" data-category="insights">
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/insights?tab=reports"
            @click.prevent="handleNavClick('/insights?tab=reports')"
            :class="['drawer-item', (currentPath.value === '/insights' || (currentPath.value && currentPath.value.startsWith('/insights'))) && route.query.tab === 'reports' ? 'drawer-item-active' : '']"
          >
            <FileText class="item-icon" />
            <span>Reports</span>
          </a>
          <a
            href="/compliance-trends"
            @click.prevent="handleNavClick('/compliance-trends')"
            :class="['drawer-item', isActive('/compliance-trends') ? 'drawer-item-active' : '']"
          >
            <TrendingUp class="item-icon" />
            <span>Compliance Trends</span>
          </a>
        </div>
      </div>

      <!-- Admin Category -->
      <div v-if="activeCategory === 'admin'" class="drawer-category" data-category="admin">
        <div class="category-items" style="padding: 0 12px 16px;">
          <a
            href="/identity-providers"
            @click.prevent="handleNavClick('/identity-providers')"
            :class="['drawer-item', isActive('/identity-providers') ? 'drawer-item-active' : '']"
          >
            <UserCog class="item-icon" />
            <span>Identity Provider Integration</span>
          </a>
          <a
            href="/compliance"
            @click.prevent="handleNavClick('/compliance')"
            :class="['drawer-item', isActive('/compliance') ? 'drawer-item-active' : '']"
          >
            <CheckCircle2 class="item-icon" />
            <span>Compliance Overview</span>
          </a>
          <a
            href="/compliance/nist-800-207"
            @click.prevent="handleNavClick('/compliance/nist-800-207')"
            :class="['drawer-item', isActive('/compliance/nist-800-207') ? 'drawer-item-active' : '']"
          >
            <ShieldCheck class="item-icon" />
            <span>NIST 800-207</span>
          </a>
        </div>
      </div>

    </nav>
  </aside>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  Shield,
  Folder,
  Settings,
  Globe,
  Lock,
  Users,
  Database,
  FileCheck,
  ChevronLeft,
  Menu,
  FileSearch,
  UserCog,
  Network,
  ShieldCheck,
  FileX,
  Server,
  TestTube,
  History,
  CheckCircle2,
  TrendingUp,
  AlertTriangle,
  AlertCircle,
  LayoutDashboard,
  Battery,
  Layers,
  List,
  BookOpen,
  FileText
} from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();
const currentPath = ref(route.path);
const isCollapsed = ref(true);
const activeCategory = ref<string | null>(null);

// Test pages
const testPages = [
  '/tests',
  '/tests/batteries', '/tests/harnesses', '/tests/suites',
  '/tests/library', '/tests/findings', '/tests/configurations',
  '/tests/history', '/test-configurations'
];

// Access Control pages
const accessControlPages = [
  '/policies', '/resources', '/tests/user-simulation',
  '/tests/policy-validation', '/policy-validation', '/users'
];

// Platform Config pages
const platformConfigPages = [
  '/configuration-validation'
];

// Data Security pages
const dataSecurityPages = [
  '/datasets', '/contracts'
];

// Insights pages
const insightsPages = [
  '/insights',
  '/compliance-trends',
  '/reports'
];

// Admin pages
const adminPages = [
  '/admin',
  '/identity-providers',
  '/compliance',
  '/compliance/nist-800-207'
];

// Determine active category based on current route
const getCategoryFromRoute = (path: string): string | null => {
  // Check if it's a test page
  if (path === '/tests' || path.startsWith('/tests/') ||
      testPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'tests';
  }
  // Check if it's an access control page
  if (accessControlPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'access-control';
  }
  // Check if it's a platform config page
  if (platformConfigPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'platform-config';
  }
  // Check if it's a data security page
  if (dataSecurityPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'data-security';
  }
  // Check if it's an insights page
  if (path === '/insights' || path.startsWith('/insights') ||
      insightsPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'insights';
  }
  // Check if it's an admin page
  if (path === '/admin' || path.startsWith('/admin/') ||
      adminPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'admin';
  }
  return null;
};

// Listen for category clicks from sidebar
const handleCategoryClick = (event: CustomEvent) => {
  const category = event.detail?.category;
  if (category) {
    activeCategory.value = category;
    if (isCollapsed.value) {
      isCollapsed.value = false;
      // Emit state change event after state update
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('drawer-state-change', { 
          detail: { isOpen: true } 
        }));
      }, 0);
    }
  }
};

const toggleDrawer = () => {
  isCollapsed.value = !isCollapsed.value;
  // If closing, clear active category
  if (isCollapsed.value) {
    activeCategory.value = null;
  }
  // Emit state change event - isOpen is true when drawer is NOT collapsed
  const isOpen = !isCollapsed.value;
  setTimeout(() => {
    window.dispatchEvent(new CustomEvent('drawer-state-change', { 
      detail: { isOpen } 
    }));
  }, 0);
};

onMounted(() => {
  window.addEventListener('open-drawer', handleCategoryClick as EventListener);
  // Initialize active category based on current route
  const category = getCategoryFromRoute(route.path);
  if (category) {
    activeCategory.value = category;
    // If we're on a category page, open the drawer
    if (isCollapsed.value) {
      isCollapsed.value = false;
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('drawer-state-change', { 
          detail: { isOpen: true } 
        }));
      }, 0);
    } else {
      // Drawer is already open, just emit the state
      window.dispatchEvent(new CustomEvent('drawer-state-change', { 
        detail: { isOpen: true } 
      }));
    }
  }
});

onBeforeUnmount(() => {
  window.removeEventListener('open-drawer', handleCategoryClick as EventListener);
});

const isActive = (path: string): boolean => {
  if (!currentPath.value) return false;
  if (path === '/tests') {
    // For /tests, only match exactly /tests, not /tests/*
    return currentPath.value === '/tests';
  }
  return currentPath.value === path || currentPath.value.startsWith(path + '/');
};

const handleNavClick = (path: string) => {
  router.push(path);
};

watch(() => route.path, (newPath) => {
  currentPath.value = newPath;
  // Update active category based on route
  const category = getCategoryFromRoute(newPath);
  if (category) {
    activeCategory.value = category;
    // Auto-open drawer if navigating to a category page
    if (isCollapsed.value) {
      isCollapsed.value = false;
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('drawer-state-change', { 
          detail: { isOpen: true } 
        }));
      }, 0);
    }
  }
});
</script>

<style scoped>
.drawer {
  position: fixed;
  top: 64px;
  left: 80px;
  width: 240px;
  height: calc(100vh - 64px);
  background: linear-gradient(180deg, #1a1f2e 0%, #0f1419 100%);
  border-right: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  flex-direction: column;
  z-index: 20;
  overflow: hidden; /* Keep hidden for drawer content */
  transition: width 0.3s ease;
}

.drawer-collapsed {
  width: 0;
  overflow: visible; /* Allow toggle button to overflow when collapsed */
  border-right: none; /* Remove border when collapsed */
}

.drawer-toggle {
  position: fixed; /* Always use fixed positioning */
  top: 80px; /* 64px top nav + 16px offset */
  left: 88px; /* 80px sidebar + 8px offset */
  width: 44px; /* Increased to meet WCAG target size */
  height: 44px; /* Increased to meet WCAG target size */
  min-width: 44px; /* Ensure minimum size */
  min-height: 44px; /* Ensure minimum size */
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  z-index: 25; /* High z-index to ensure it's always on top */
  color: #4facfe;
  transition: all 0.2s;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  flex-shrink: 0; /* Prevent button from shrinking */
  visibility: visible !important; /* Ensure button is always visible */
  opacity: 1 !important; /* Ensure button is fully opaque */
  pointer-events: auto; /* Ensure button is clickable */
}

/* When drawer is open, position button inside drawer */
.drawer:not(.drawer-collapsed) .drawer-toggle {
  position: absolute;
  left: 8px;
  top: 16px;
  z-index: 22;
}

.drawer-toggle:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
  transform: scale(1.05);
}

.drawer-toggle:focus-visible {
  outline: 3px solid #4facfe;
  outline-offset: 2px;
}

.toggle-icon {
  width: 20px;
  height: 20px;
  stroke-width: 2;
  flex-shrink: 0;
  display: block;
  color: #4facfe;
  opacity: 1 !important;
  visibility: visible !important;
}

/* Ensure icons are visible and properly styled */
.drawer-toggle .toggle-icon {
  opacity: 1 !important;
  visibility: visible !important;
  color: #4facfe !important;
  stroke: currentColor;
  fill: none;
}

/* Ensure SVG icons render */
.drawer-toggle :deep(svg),
.drawer-toggle svg {
  width: 20px !important;
  height: 20px !important;
  display: block !important;
  color: #4facfe !important;
  stroke: currentColor !important;
  fill: none !important;
  opacity: 1 !important;
  visibility: visible !important;
  pointer-events: none;
}

.drawer-nav {
  flex: 1;
  padding: 24px 0;
  padding-top: 72px; /* Space for toggle button */
  display: flex;
  flex-direction: column;
  gap: 32px;
  overflow-y: auto;
  overflow-x: hidden;
  width: 100%; /* Ensure nav takes full width of drawer */
}

/* When drawer is collapsed, hide the nav but keep toggle visible */
.drawer-collapsed .drawer-nav {
  display: none;
}

.drawer-category {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.category-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 20px 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.category-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
  flex-shrink: 0;
}

.category-title {
  font-size: 0.75rem;
  font-weight: 600;
  color: #718096;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 0;
}

.category-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 24px;
}

.category-section:last-child {
  margin-bottom: 0;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 20px 6px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.08);
  margin-top: 8px;
}

.section-header:first-child {
  margin-top: 0;
}

.section-icon {
  width: 16px;
  height: 16px;
  color: #4facfe;
  flex-shrink: 0;
  opacity: 0.8;
}

.section-title {
  font-size: 0.7rem;
  font-weight: 600;
  color: #718096;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 0;
  opacity: 0.9;
}

.category-items {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 0 12px;
}

.drawer-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  color: #a0aec0;
  text-decoration: none;
  border-radius: 8px;
  transition: all 0.2s;
  font-size: 0.9rem;
  border-left: 3px solid transparent;
}

.drawer-item:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.drawer-item-active {
  background: rgba(79, 172, 254, 0.15);
  color: #4facfe;
  border-left-color: #4facfe;
}

.item-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  stroke-width: 2;
}

/* Scrollbar styling */
.drawer::-webkit-scrollbar {
  width: 4px;
}

.drawer::-webkit-scrollbar-track {
  background: transparent;
}

.drawer::-webkit-scrollbar-thumb {
  background: rgba(79, 172, 254, 0.3);
  border-radius: 2px;
}

.drawer::-webkit-scrollbar-thumb:hover {
  background: rgba(79, 172, 254, 0.5);
}
</style>

