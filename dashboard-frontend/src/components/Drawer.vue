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
      <!-- Applications Category -->
      <div v-if="activeCategory === 'applications'" :key="`applications-${activeCategory}`" class="drawer-category" data-category="applications">
        <div class="category-items category-items-padded">
          <a
            href="/applications"
            @click.prevent="handleNavClick('/applications')"
            :class="['drawer-item', isActive('/applications') && !isActive('/applications/platform-instances') ? 'drawer-item-active' : '']"
          >
            <LayoutDashboard class="item-icon" />
            <span>Overview</span>
          </a>
          <a
            href="/applications/platform-instances"
            @click.prevent="handleNavClick('/applications/platform-instances')"
            :class="['drawer-item', isActive('/applications/platform-instances') ? 'drawer-item-active' : '']"
          >
            <Settings class="item-icon" />
            <span>Platform Instances</span>
          </a>
        </div>
      </div>

      <!-- Test Design Library Category -->
      <div v-if="activeCategory === 'test-design-library'" :key="`test-design-library-${activeCategory}`" class="drawer-category" data-category="test-design-library">
        <div class="category-items category-items-padded">
          <a
            href="/tests"
            @click.prevent="handleNavClick('/tests')"
            :class="['drawer-item', isActive('/tests') ? 'drawer-item-active' : '']"
          >
            <LayoutDashboard class="item-icon" />
            <span>Overview</span>
          </a>
          <a
            href="/tests/individual"
            @click.prevent="handleNavClick('/tests/individual')"
            :class="['drawer-item', isActive('/tests/individual') ? 'drawer-item-active' : '']"
          >
            <TestTube class="item-icon" />
            <span>Tests</span>
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
            href="/tests/harnesses"
            @click.prevent="handleNavClick('/tests/harnesses')"
            :class="['drawer-item', isActive('/tests/harnesses') ? 'drawer-item-active' : '']"
          >
            <Layers class="item-icon" />
            <span>Test Harnesses</span>
          </a>
          <a
            href="/tests/batteries"
            @click.prevent="handleNavClick('/tests/batteries')"
            :class="['drawer-item', isActive('/tests/batteries') ? 'drawer-item-active' : '']"
          >
            <Battery class="item-icon" />
            <span>Test Batteries</span>
          </a>
        </div>
      </div>

      <!-- Policies & Config Category -->
      <div v-if="activeCategory === 'policies-config'" :key="`policies-config-${activeCategory}`" class="drawer-category" data-category="policies-config">
        <div class="category-items category-items-padded">
          <!-- Overview -->
          <a
            href="/policies"
            @click.prevent="handleNavClick('/policies')"
            :class="['drawer-item', isActive('/policies') ? 'drawer-item-active' : '']"
          >
            <LayoutDashboard class="item-icon" />
            <span>Overview</span>
          </a>
          
          <!-- Access Control Policies Section -->
          <div class="category-section">
            <div class="section-header">
              <Shield class="section-icon" />
              <span class="section-title">Access Control</span>
            </div>
            <a
              href="/policies/access-control"
              @click.prevent="handleNavClick('/policies/access-control')"
              :class="['drawer-item', isActive('/policies/access-control') ? 'drawer-item-active' : '']"
            >
              <Shield class="item-icon" />
              <span>Access Control</span>
            </a>
            <a
              href="/policies/exceptions"
              @click.prevent="handleNavClick('/policies/exceptions')"
              :class="['drawer-item', isActive('/policies/exceptions') ? 'drawer-item-active' : '']"
            >
              <AlertTriangle class="item-icon" />
              <span>Exceptions</span>
            </a>
          </div>

          <!-- Data Policies Section -->
          <div class="category-section">
            <div class="section-header">
              <Database class="section-icon" />
              <span class="section-title">Data Policies</span>
            </div>
            <a
              href="/policies/data-classification"
              @click.prevent="handleNavClick('/policies/data-classification')"
              :class="['drawer-item', isActive('/policies/data-classification') ? 'drawer-item-active' : '']"
            >
              <FileText class="item-icon" />
              <span>Data Classification</span>
            </a>
            <a
              href="/policies/data-contracts"
              @click.prevent="handleNavClick('/policies/data-contracts')"
              :class="['drawer-item', isActive('/policies/data-contracts') ? 'drawer-item-active' : '']"
            >
              <Database class="item-icon" />
              <span>Data Contracts</span>
            </a>
            <a
              href="/policies/standards-mapping"
              @click.prevent="handleNavClick('/policies/standards-mapping')"
              :class="['drawer-item', isActive('/policies/standards-mapping') ? 'drawer-item-active' : '']"
            >
              <CheckCircle2 class="item-icon" />
              <span>Standards Mapping</span>
            </a>
          </div>

          <!-- Platform Baselines Section -->
          <div class="category-section">
            <div class="section-header">
              <Settings class="section-icon" />
              <span class="section-title">Platform Baselines</span>
            </div>
            <a
              href="/policies/salesforce"
              @click.prevent="handleNavClick('/policies/salesforce')"
              :class="['drawer-item', isActive('/policies/salesforce') ? 'drawer-item-active' : '']"
            >
              <Cloud class="item-icon" />
              <span>Salesforce</span>
            </a>
            <a
              href="/policies/elastic"
              @click.prevent="handleNavClick('/policies/elastic')"
              :class="['drawer-item', isActive('/policies/elastic') ? 'drawer-item-active' : '']"
            >
              <Server class="item-icon" />
              <span>Elastic</span>
            </a>
            <a
              href="/policies/idp-platform"
              @click.prevent="handleNavClick('/policies/idp-platform')"
              :class="['drawer-item', isActive('/policies/idp-platform') ? 'drawer-item-active' : '']"
            >
              <Container class="item-icon" />
              <span>IDP / Kubernetes</span>
            </a>
            <a
              href="/policies/servicenow"
              @click.prevent="handleNavClick('/policies/servicenow')"
              :class="['drawer-item', isActive('/policies/servicenow') ? 'drawer-item-active' : '']"
            >
              <Workflow class="item-icon" />
              <span>ServiceNow</span>
            </a>
          </div>

          <!-- Configuration & Testing Section -->
          <div class="category-section">
            <div class="section-header">
              <FileCheck class="section-icon" />
              <span class="section-title">Configuration & Testing</span>
            </div>
            <a
              href="/resources"
              @click.prevent="handleNavClick('/resources')"
              :class="['drawer-item', isActive('/resources') ? 'drawer-item-active' : '']"
            >
              <Database class="item-icon" />
              <span>Resources</span>
            </a>
            <a
              href="/environment-config-testing"
              @click.prevent="handleNavClick('/environment-config-testing')"
              :class="['drawer-item', isActive('/environment-config-testing') ? 'drawer-item-active' : '']"
            >
              <Settings class="item-icon" />
              <span>Environment Config Testing</span>
            </a>
            <a
              href="/salesforce-experience-cloud"
              @click.prevent="handleNavClick('/salesforce-experience-cloud')"
              :class="['drawer-item', isActive('/salesforce-experience-cloud') ? 'drawer-item-active' : '']"
            >
              <Cloud class="item-icon" />
              <span>Salesforce Experience Cloud</span>
            </a>
          </div>
        </div>
      </div>


      <!-- Admin Category -->
      <div v-if="activeCategory === 'admin'" :key="`admin-${activeCategory}`" class="drawer-category" data-category="admin">
        <div class="category-items category-items-padded">
          <a
            href="/admin"
            @click.prevent="handleNavClick('/admin')"
            :class="['drawer-item', currentPath.value === '/admin' ? 'drawer-item-active' : '']"
          >
            <LayoutDashboard class="item-icon" />
            <span>Overview</span>
          </a>
          <a
            href="/identity-providers"
            @click.prevent="handleNavClick('/identity-providers')"
            :class="['drawer-item', isActive('/identity-providers') ? 'drawer-item-active' : '']"
          >
            <UserCog class="item-icon" />
            <span>Identity Provider Integration</span>
          </a>
          <a
            href="/admin/integrations/iam"
            @click.prevent="handleNavClick('/admin/integrations/iam')"
            :class="['drawer-item', isActive('/admin/integrations/iam') ? 'drawer-item-active' : '']"
          >
            <KeyRound class="item-icon" />
            <span>IAM Integrations</span>
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
import { ref, watch, onMounted, onBeforeUnmount, nextTick } from 'vue';
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
  FileText,
  KeyRound,
  Container,
  Cloud,
  BarChart3,
  PlayCircle,
  Workflow
} from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();
const currentPath = ref(route.path);
const isCollapsed = ref(true);
const activeCategory = ref<string | null>(null);

// Applications pages
const applicationsPages = [
  '/applications',
  '/applications/platform-instances'
];

// Test Design Library pages
const testDesignLibraryPages = [
  '/tests',
  '/tests/batteries', '/tests/harnesses', '/tests/suites',
  '/tests/individual', '/tests/findings',
  '/tests/history'
];

// Policies & Config pages
const policiesConfigPages = [
  '/policies',
  '/policies/access-control',
  '/policies/data-classification',
  '/policies/exceptions',
  '/policies/standards-mapping',
  '/policies/data-contracts',
  '/policies/salesforce',
  '/policies/elastic',
  '/policies/idp-platform',
  '/policies/servicenow',
  '/resources',
  '/environment-config-testing',
  '/salesforce-experience-cloud'
];

// Admin pages
const adminPages = [
  '/admin',
  '/identity-providers',
  '/admin/integrations/iam',
  '/compliance',
  '/compliance/nist-800-207'
];


// Determine active category based on current route
const getCategoryFromRoute = (path: string): string | null => {
  // Check if it's an applications page
  if (path === '/applications' || path.startsWith('/applications/') ||
      applicationsPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'applications';
  }
  // Check if it's a test design library page
  if (path === '/tests' || path.startsWith('/tests/') ||
      testDesignLibraryPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'test-design-library';
  }
  // Check if it's a policies & config page
  if (policiesConfigPages.some(page => path === page || path.startsWith(page + '/'))) {
    return 'policies-config';
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
    // Always update the category when sidebar item is clicked
    // Use nextTick to ensure reactivity updates are processed
    activeCategory.value = category;
    nextTick(() => {
      if (isCollapsed.value) {
        isCollapsed.value = false;
        // Emit state change event after state update
        setTimeout(() => {
          window.dispatchEvent(new CustomEvent('drawer-state-change', { 
            detail: { isOpen: true } 
          }));
        }, 0);
      }
    });
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
  if (path === '/policies') {
    // For /policies, only match exactly /policies, not /policies/*
    return currentPath.value === '/policies';
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
    // Always update category when route changes to a category page
    // This ensures the drawer shows the correct category for the current route
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
  } else {
    // If navigating to a non-category page, only clear category if drawer is collapsed
    if (isCollapsed.value) {
      activeCategory.value = null;
    }
  }
});
</script>

<style scoped>
.drawer {
  position: fixed;
  top: calc(var(--spacing-2xl) + var(--spacing-md)); /* 64px - matches TopNav height */
  left: calc(var(--spacing-2xl) + var(--spacing-xl)); /* 80px - matches Sidebar width */
  width: calc(var(--spacing-xl) * 7.5); /* 240px */
  height: calc(100vh - calc(var(--spacing-2xl) + var(--spacing-md)));
  background: linear-gradient(180deg, var(--color-bg-secondary) 0%, var(--color-bg-primary) 100%);
  border-right: var(--border-width-thin) solid var(--border-color-primary);
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
  top: calc(var(--spacing-2xl) + var(--spacing-xl)); /* 64px top nav + 16px offset */
  left: calc(var(--spacing-2xl) + var(--spacing-xl) + var(--spacing-sm)); /* 80px sidebar + 8px offset */
  width: calc(var(--spacing-xl) + var(--spacing-md)); /* 44px - WCAG target size */
  height: calc(var(--spacing-xl) + var(--spacing-md)); /* 44px - WCAG target size */
  min-width: 44px; /* Ensure minimum size */
  min-height: 44px; /* Ensure minimum size */
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  z-index: 25; /* High z-index to ensure it's always on top */
  color: var(--color-primary);
  transition: var(--transition-all);
  box-shadow: var(--shadow-sm);
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
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
  transform: scale(1.05);
}

.drawer-toggle:focus-visible {
  outline: 3px solid var(--color-primary);
  outline-offset: 2px;
}

.toggle-icon {
  width: 20px;
  height: 20px;
  stroke-width: 2;
  flex-shrink: 0;
  display: block;
  color: var(--color-primary);
  opacity: 1 !important;
  visibility: visible !important;
}

/* Ensure icons are visible and properly styled */
.drawer-toggle .toggle-icon {
  opacity: 1 !important;
  visibility: visible !important;
  color: var(--color-primary) !important;
  stroke: currentColor;
  fill: none;
}

/* Ensure SVG icons render */
.drawer-toggle :deep(svg),
.drawer-toggle svg {
  width: 20px !important;
  height: 20px !important;
  display: block !important;
  color: var(--color-primary) !important;
  stroke: currentColor !important;
  fill: none !important;
  opacity: 1 !important;
  visibility: visible !important;
  pointer-events: none;
}

.drawer-nav {
  flex: 1;
  padding: var(--spacing-lg) 0;
  padding-top: 72px; /* Space for toggle button */
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
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
  gap: var(--spacing-md);
}

.category-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 20px var(--spacing-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.category-icon {
  width: 18px;
  height: 18px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.category-title {
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 0;
}

.category-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
}

.category-section:last-child {
  margin-bottom: 0;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 20px 6px;
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
  margin-top: var(--spacing-sm);
}

.section-header:first-child {
  margin-top: 0;
}

.section-icon {
  width: 16px;
  height: 16px;
  color: var(--color-primary);
  flex-shrink: 0;
  opacity: 0.8;
}

.section-title {
  font-size: 0.7rem;
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 0;
  opacity: 0.9;
}

.category-items {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  padding: 0 var(--spacing-md);
}

.category-items-padded {
  padding: 0 var(--spacing-md) var(--spacing-md);
}

.category-spacer {
  height: var(--spacing-md);
}

.drawer-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: 10px var(--spacing-md);
  color: var(--color-text-secondary);
  text-decoration: none;
  border-radius: var(--border-radius-md);
  transition: var(--transition-all);
  font-size: var(--font-size-sm);
  border-left: 3px solid transparent;
}

.drawer-item:hover {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.drawer-item-active {
  background: rgba(79, 172, 254, 0.15);
  color: var(--color-primary);
  border-left-color: var(--color-primary);
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
  background: var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
}

.drawer::-webkit-scrollbar-thumb:hover {
  background: var(--border-color-primary-active);
}
</style>

