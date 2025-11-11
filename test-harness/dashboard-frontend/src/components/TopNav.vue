<template>
  <nav 
    class="top-nav"
    role="navigation" 
    aria-label="Top navigation"
  >
    <div class="nav-container">
      <!-- Left: Menu Button (Mobile) and Logo -->
      <div class="nav-left">
        <button
          @click="toggleDrawer"
          class="menu-button"
          title="Open menu"
          aria-label="Open navigation menu"
        >
          <Menu class="menu-icon" />
        </button>
        <router-link to="/" class="logo-link">
          <Shield class="logo-icon" />
          <span class="logo-text">Sentinel</span>
        </router-link>
      </div>
      
      <!-- Center: Search Bar -->
      <div class="nav-center">
        <div class="search-container">
          <Search class="search-icon" />
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search compliance reports, tests, policies..."
            @focus="showSearchResults = true"
            @keydown.escape="closeSearch"
            class="search-input"
            aria-label="Search dashboard"
          />
          <button
            v-if="searchQuery"
            @click="clearSearch"
            class="clear-button"
            aria-label="Clear search"
          >
            <X class="clear-icon" />
          </button>
          
          <!-- Search Results Dropdown -->
          <div
            v-if="showSearchResults && searchQuery.trim()"
            class="search-results"
            role="listbox"
          >
            <div v-if="filteredResults.length === 0" class="search-empty">
              <Search class="empty-icon" />
              <p>No results found</p>
            </div>
            <div v-else class="search-results-list">
              <div
                v-for="(result, index) in filteredResults"
                :key="index"
                @click="selectResult(result)"
                class="search-result-item"
                role="option"
              >
                <div class="result-icon">
                  <FileText v-if="result.type === 'report'" />
                  <ShieldCheck v-else-if="result.type === 'test'" />
                  <FileCode v-else />
                </div>
                <div class="result-content">
                  <h4>{{ result.title }}</h4>
                  <p>{{ result.description }}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: Actions -->
      <div class="nav-right">
        <!-- Refresh Button -->
        <button
          @click="refreshDashboard"
          class="nav-button"
          title="Refresh dashboard"
          aria-label="Refresh dashboard data"
        >
          <RefreshCw class="nav-icon" :class="{ 'spinning': isRefreshing }" />
        </button>

        <!-- Settings Button -->
        <button
          @click="showSettings = !showSettings"
          class="nav-button"
          title="Settings"
          aria-label="Open settings"
        >
          <Settings class="nav-icon" />
        </button>

        <!-- Notifications -->
        <div class="relative" ref="notificationsContainer">
          <button
            @click="toggleNotifications"
            class="nav-button notification-button"
            :title="`Notifications${totalNotificationCount > 0 ? `, ${totalNotificationCount} unread` : ''}`"
            :aria-label="`Notifications${totalNotificationCount > 0 ? `, ${totalNotificationCount} unread` : ''}`"
            :aria-expanded="showNotifications"
            aria-haspopup="true"
          >
            <Bell class="nav-icon" />
            <span 
              v-if="totalNotificationCount > 0"
              class="notification-badge"
              :class="breakingChangeNotifications.length > 0 ? 'badge-critical' : 'badge-normal'"
              aria-hidden="true"
            >
              {{ totalNotificationCount > 9 ? '9+' : totalNotificationCount }}
            </span>
          </button>
          
          <!-- Notifications Dropdown -->
          <div
            v-if="showNotifications"
            class="notification-dropdown"
            role="menu"
            aria-label="Notifications"
          >
                <!-- Header -->
                <div class="notification-header">
                  <h3 class="notification-title">Notifications</h3>
                  <button
                    @click="closeNotifications"
                    class="notification-close"
                    aria-label="Close notifications"
                  >
                    <X class="close-icon" />
                  </button>
                </div>
                
                <!-- Tabs -->
                <div class="notification-tabs">
                  <button
                    @click="notificationTab = 'all'"
                    class="notification-tab"
                    :class="{ 'active': notificationTab === 'all' }"
                  >
                    All
                    <span v-if="totalNotificationCount > 0" class="tab-badge">
                      {{ totalNotificationCount }}
                    </span>
                  </button>
                  <button
                    @click="notificationTab = 'breaking'"
                    class="notification-tab"
                    :class="{ 'active': notificationTab === 'breaking' }"
                  >
                    Breaking Changes
                    <span v-if="breakingChangeNotifications.length > 0" class="tab-badge tab-badge-critical">
                      {{ breakingChangeNotifications.length }}
                    </span>
                  </button>
                  <button
                    @click="notificationTab = 'activity'"
                    class="notification-tab"
                    :class="{ 'active': notificationTab === 'activity' }"
                  >
                    Activity
                    <span v-if="recentActivity.length > 0" class="tab-badge">
                      {{ recentActivity.length }}
                    </span>
                  </button>
                </div>
                
                <!-- Notification List -->
                <div class="notification-list">
                  <!-- All Tab -->
                  <div v-if="notificationTab === 'all'">
                    <div v-if="totalNotificationCount === 0" class="notification-empty">
                      <Bell class="empty-icon" />
                      <p>No notifications</p>
                    </div>
                    <div v-else>
                      <!-- Breaking Changes First -->
                      <div
                        v-for="notification in breakingChangeNotifications"
                        :key="`breaking-${notification.id}`"
                        @click="handleNotificationClick(notification)"
                        class="notification-item notification-item-breaking"
                      >
                        <div class="notification-icon breaking-icon">
                          <AlertTriangle class="icon" />
                        </div>
                        <div class="notification-content">
                          <div class="notification-header-item">
                            <h4>Breaking Change</h4>
                            <span class="notification-tag breaking-tag">{{ notification.componentName }}</span>
                          </div>
                          <p class="notification-message">{{ notification.message }}</p>
                          <p class="notification-time">{{ formatRelativeTime(notification.timestamp) }}</p>
                        </div>
                      </div>
                      
                      <!-- Activity -->
                      <div
                        v-for="activity in recentActivity"
                        :key="activity.id"
                        @click="handleActivityClick(activity)"
                        class="notification-item"
                      >
                        <div class="notification-icon activity-icon">
                          <FileText class="icon" />
                        </div>
                        <div class="notification-content">
                          <div class="notification-header-item">
                            <h4>{{ activity.title }}</h4>
                          </div>
                          <p class="notification-message">{{ activity.description }}</p>
                          <p class="notification-time">{{ formatRelativeTime(activity.timestamp) }}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <!-- Breaking Changes Tab -->
                  <div v-else-if="notificationTab === 'breaking'">
                    <div v-if="breakingChangeNotifications.length === 0" class="notification-empty">
                      <AlertTriangle class="empty-icon" />
                      <p>No breaking changes</p>
                    </div>
                    <div
                      v-for="notification in breakingChangeNotifications"
                      :key="notification.id"
                      @click="handleNotificationClick(notification)"
                      class="notification-item notification-item-breaking"
                    >
                      <div class="notification-icon breaking-icon">
                        <AlertTriangle class="icon" />
                      </div>
                      <div class="notification-content">
                        <div class="notification-header-item">
                          <h4>Breaking Change</h4>
                          <span class="notification-tag breaking-tag">{{ notification.componentName }}</span>
                        </div>
                        <p class="notification-message">{{ notification.message }}</p>
                        <p class="notification-time">{{ formatRelativeTime(notification.timestamp) }}</p>
                      </div>
                    </div>
                  </div>
                  
                  <!-- Activity Tab -->
                  <div v-else-if="notificationTab === 'activity'">
                    <div v-if="recentActivity.length === 0" class="notification-empty">
                      <FileText class="empty-icon" />
                      <p>No recent activity</p>
                    </div>
                    <div
                      v-for="activity in recentActivity"
                      :key="activity.id"
                      @click="handleActivityClick(activity)"
                      class="notification-item"
                    >
                      <div class="notification-icon activity-icon">
                        <FileText class="icon" />
                      </div>
                      <div class="notification-content">
                        <div class="notification-header-item">
                          <h4>{{ activity.title }}</h4>
                        </div>
                        <p class="notification-message">{{ activity.description }}</p>
                        <p class="notification-time">{{ formatRelativeTime(activity.timestamp) }}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
        </div>

        <!-- User Avatar -->
        <button
          class="user-avatar"
          title="User menu"
          aria-label="User menu"
        >
          <div class="avatar-circle">
            {{ userInitials }}
          </div>
        </button>

        <!-- App Picker -->
        <button
          class="nav-button app-picker"
          title="Switch App"
          aria-label="Switch application"
        >
          <span class="material-symbols-outlined app-picker-icon">apps</span>
        </button>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { useRouter } from 'vue-router';
import { Shield, Search, X, FileText, ShieldCheck, FileCode, RefreshCw, Settings, Menu, Bell, AlertTriangle } from 'lucide-vue-next';

const router = useRouter();

const searchQuery = ref('');
const showSearchResults = ref(false);
const isRefreshing = ref(false);
const showSettings = ref(false);
const drawerOpen = ref(false);
const showNotifications = ref(false);
const notificationTab = ref<'all' | 'breaking' | 'activity'>('all');
const notificationsContainer = ref<HTMLElement | null>(null);

// Mock notification data
const breakingChangeNotifications = ref([
  {
    id: '1',
    componentName: 'TestSuite',
    message: 'Test suite configuration has been updated with breaking changes',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
    componentId: 'test-suite'
  }
]);

const recentActivity = ref([
  {
    id: '1',
    title: 'Test Execution Completed',
    description: 'Compliance test suite ran successfully with 95% pass rate',
    timestamp: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
    reviewId: 'test-123'
  },
  {
    id: '2',
    title: 'New Policy Added',
    description: 'RBAC policy for data access has been configured',
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000), // 4 hours ago
    reviewId: 'policy-456'
  }
]);

const totalNotificationCount = computed(() => {
  return breakingChangeNotifications.value.length + recentActivity.value.length;
});

// Mock search results - in real app, this would come from API
const searchResults = ref([
  { type: 'report', title: 'Compliance Report - Q4 2024', description: 'Quarterly compliance summary', path: '/reports/q4-2024' },
  { type: 'test', title: 'Access Control Test Suite', description: 'RBAC and ABAC policy tests', path: '/tests/access-control' },
  { type: 'policy', title: 'Data Classification Policy', description: 'PII handling and data classification rules', path: '/policies/data-classification' },
]);

const filteredResults = computed(() => {
  if (!searchQuery.value.trim()) return [];
  const query = searchQuery.value.toLowerCase();
  return searchResults.value.filter(result =>
    result.title.toLowerCase().includes(query) ||
    result.description.toLowerCase().includes(query)
  ).slice(0, 5);
});

const userInitials = computed(() => {
  // In real app, get from auth
  return 'AD';
});

const clearSearch = () => {
  searchQuery.value = '';
  showSearchResults.value = false;
};

const closeSearch = () => {
  showSearchResults.value = false;
};

const selectResult = (result: any) => {
  // In real app, navigate to result.path
  console.log('Navigate to:', result.path);
  closeSearch();
  searchQuery.value = '';
};

const refreshDashboard = async () => {
  isRefreshing.value = true;
  // Emit event to parent to refresh
  window.dispatchEvent(new CustomEvent('refresh-dashboard'));
  setTimeout(() => {
    isRefreshing.value = false;
  }, 1000);
};

const toggleDrawer = () => {
  drawerOpen.value = !drawerOpen.value;
  window.dispatchEvent(new CustomEvent('toggle-drawer', { detail: { open: drawerOpen.value } }));
};

const toggleNotifications = () => {
  showNotifications.value = !showNotifications.value;
  if (showNotifications.value) {
    showSearchResults.value = false;
    showSettings.value = false;
  }
};

const closeNotifications = () => {
  showNotifications.value = false;
};

const handleNotificationClick = (notification: any) => {
  // Navigate to component or handle notification click
  console.log('Notification clicked:', notification);
  closeNotifications();
};

const handleActivityClick = (activity: any) => {
  // Navigate to activity or handle click
  console.log('Activity clicked:', activity);
  closeNotifications();
};

const formatRelativeTime = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

const handleClickOutside = (event: MouseEvent) => {
  const target = event.target as HTMLElement;
  if (showSearchResults.value && !target.closest('.search-container')) {
    closeSearch();
  }
  if (showNotifications.value && notificationsContainer.value && !notificationsContainer.value.contains(target)) {
    closeNotifications();
  }
};

onMounted(() => {
  document.addEventListener('click', handleClickOutside);
});

onBeforeUnmount(() => {
  document.removeEventListener('click', handleClickOutside);
});
</script>

<style scoped>
.top-nav {
  position: sticky;
  top: 0;
  z-index: 40;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}

.nav-container {
  display: flex;
  align-items: center;
  height: 64px;
  max-width: 1600px;
  margin: 0 auto;
  padding: 0 24px;
  gap: 24px;
}

.nav-left {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 16px;
}

.menu-button {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  padding: 0;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
}

.menu-button:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.menu-icon {
  width: 20px;
  height: 20px;
}

@media (min-width: 1024px) {
  .menu-button {
    display: none;
  }
}

.logo-link {
  display: flex;
  align-items: center;
  gap: 12px;
  text-decoration: none;
  transition: opacity 0.2s;
}

.logo-link:hover {
  opacity: 0.8;
}

.logo-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
  stroke-width: 2;
}

.logo-text {
  font-size: 1.5rem;
  font-weight: 700;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: -0.5px;
}

.nav-center {
  flex: 1;
  display: flex;
  justify-content: center;
  min-width: 0;
}

.search-container {
  position: relative;
  width: 100%;
  max-width: 600px;
}

.search-input {
  width: 100%;
  padding: 10px 40px 10px 40px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
  background: rgba(15, 20, 25, 0.8);
}

.search-input::placeholder {
  color: #718096;
}

.search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  width: 18px;
  height: 18px;
  color: #718096;
  pointer-events: none;
}

.clear-button {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  padding: 4px;
  background: transparent;
  border: none;
  cursor: pointer;
  color: #718096;
  transition: color 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.clear-button:hover {
  color: #ffffff;
}

.clear-icon {
  width: 16px;
  height: 16px;
}

.search-results {
  position: absolute;
  top: calc(100% + 8px);
  left: 0;
  right: 0;
  max-height: 400px;
  overflow-y: auto;
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  z-index: 50;
}

.search-empty {
  padding: 40px;
  text-align: center;
  color: #718096;
}

.empty-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.search-results-list {
  padding: 8px;
}

.search-result-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.2s;
}

.search-result-item:hover {
  background: rgba(79, 172, 254, 0.1);
}

.result-icon {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 6px;
  color: #4facfe;
  flex-shrink: 0;
}

.result-content {
  flex: 1;
  min-width: 0;
}

.result-content h4 {
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
  margin: 0 0 4px 0;
}

.result-content p {
  color: #a0aec0;
  font-size: 0.8rem;
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nav-right {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.nav-button {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  padding: 0;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
}

.nav-button:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.nav-icon {
  width: 20px;
  height: 20px;
  color: inherit;
}

.app-picker {
  color: #a0aec0;
}

.app-picker:hover {
  background-color: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.app-picker-icon {
  font-size: 24px;
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.nav-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.user-avatar {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  padding: 0;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.user-avatar:hover {
  background: rgba(79, 172, 254, 0.1);
}

.avatar-circle {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #0f1419;
  font-weight: 600;
  font-size: 0.875rem;
}

.notification-button {
  position: relative;
}

.notification-badge {
  position: absolute;
  top: 4px;
  right: 4px;
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0 4px;
}

.badge-normal {
  background: #4facfe;
  color: #0f1419;
}

.badge-critical {
  background: #fc8181;
  color: #ffffff;
}

.notification-dropdown {
  position: absolute;
  right: 0;
  top: calc(100% + 8px);
  width: 384px;
  max-height: 600px;
  overflow: hidden;
  border-radius: 12px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  z-index: 1000;
}

.notification-header {
  padding: 16px 20px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.notification-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.notification-close {
  padding: 4px;
  background: transparent;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.notification-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 18px;
  height: 18px;
}

.notification-tabs {
  display: flex;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.notification-tab {
  flex: 1;
  padding: 12px 16px;
  font-size: 0.875rem;
  font-weight: 500;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.notification-tab:hover {
  color: #4facfe;
}

.notification-tab.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-badge {
  padding: 2px 6px;
  border-radius: 10px;
  font-size: 0.75rem;
  font-weight: 600;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.tab-badge-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.notification-list {
  overflow-y: auto;
  max-height: 500px;
}

.notification-empty {
  padding: 64px 32px;
  text-align: center;
}

.notification-empty .empty-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto 16px;
  color: #718096;
  opacity: 0.5;
}

.notification-empty p {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0;
}

.notification-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 16px;
  cursor: pointer;
  transition: background 0.2s;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.notification-item:hover {
  background: rgba(79, 172, 254, 0.05);
}

.notification-item-breaking {
  border-left: 4px solid #fc8181;
  background: rgba(252, 129, 129, 0.05);
}

.notification-icon {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.breaking-icon {
  background: rgba(252, 129, 129, 0.2);
}

.breaking-icon .icon {
  width: 16px;
  height: 16px;
  color: #fc8181;
}

.activity-icon {
  background: rgba(79, 172, 254, 0.2);
}

.activity-icon .icon {
  width: 16px;
  height: 16px;
  color: #4facfe;
}

.notification-content {
  flex: 1;
  min-width: 0;
}

.notification-header-item {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.notification-header-item h4 {
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.notification-tag {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.breaking-tag {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.notification-message {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 4px 0;
  line-height: 1.4;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.notification-time {
  font-size: 0.75rem;
  color: #718096;
  margin: 0;
}

/* Responsive */
@media (max-width: 768px) {
  .logo-text {
    display: none;
  }
  
  .nav-container {
    padding: 0 16px;
    gap: 12px;
  }
  
  .search-container {
    max-width: none;
  }
  
  .search-input {
    font-size: 0.85rem;
    padding: 8px 36px 8px 36px;
  }
}
</style>

