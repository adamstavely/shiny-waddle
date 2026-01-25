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
          <span class="logo-text">Heimdall</span>
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
          @click="router.push('/settings')"
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
              :class="criticalFindingNotifications.length > 0 ? 'badge-critical' : 'badge-normal'"
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
                    <span v-if="unreadCount > 0" class="tab-badge">
                      {{ unreadCount }}
                    </span>
                  </button>
                  <button
                    @click="notificationTab = 'score-drops'"
                    class="notification-tab"
                    :class="{ 'active': notificationTab === 'score-drops' }"
                  >
                    Score Drops
                    <span v-if="scoreDropNotifications.length > 0" class="tab-badge">
                      {{ scoreDropNotifications.filter(n => !n.read).length }}
                    </span>
                  </button>
                  <button
                    @click="notificationTab = 'findings'"
                    class="notification-tab"
                    :class="{ 'active': notificationTab === 'findings' }"
                  >
                    Critical Findings
                    <span v-if="criticalFindingNotifications.length > 0" class="tab-badge tab-badge-critical">
                      {{ criticalFindingNotifications.filter(n => !n.read).length }}
                    </span>
                  </button>
                  <button
                    @click="notificationTab = 'approvals'"
                    class="notification-tab"
                    :class="{ 'active': notificationTab === 'approvals' }"
                  >
                    Approvals
                    <span v-if="approvalNotifications.length > 0" class="tab-badge">
                      {{ approvalNotifications.filter(n => !n.read).length }}
                    </span>
                  </button>
                </div>
                
                <!-- Mark All Read Button -->
                <div v-if="unreadCount > 0" class="notification-actions">
                  <button @click="markAllAsRead" class="mark-all-read-btn">
                    Mark all as read
                  </button>
                </div>
                
                <!-- Notification List -->
                <div class="notification-list">
                  <div v-if="notificationsLoading" class="notification-loading">
                    <p>Loading notifications...</p>
                  </div>
                  <div v-else-if="filteredNotifications.length === 0" class="notification-empty">
                    <Bell class="empty-icon" />
                    <p>No notifications</p>
                  </div>
                  <div v-else>
                    <div
                      v-for="notification in filteredNotifications"
                      :key="notification.id"
                      @click="handleNotificationClick(notification)"
                      class="notification-item"
                      :class="{
                        'notification-item-unread': !notification.read,
                        'notification-item-critical': notification.type === NotificationType.CRITICAL_FINDING,
                        'notification-item-score-drop': notification.type === NotificationType.SCORE_DROP,
                      }"
                    >
                      <div class="notification-icon" :class="getNotificationIconClass(notification.type)">
                        <component :is="getNotificationIcon(notification.type)" class="icon" />
                      </div>
                      <div class="notification-content">
                        <div class="notification-header-item">
                          <h4>{{ notification.title }}</h4>
                          <span v-if="!notification.read" class="unread-dot"></span>
                        </div>
                        <p class="notification-message">{{ notification.message }}</p>
                        <div v-if="notification.metadata?.scoreChange" class="notification-meta">
                          <span class="score-change" :class="notification.metadata.scoreChange < 0 ? 'negative' : 'positive'">
                            {{ notification.metadata.scoreChange > 0 ? '+' : '' }}{{ notification.metadata.scoreChange }} points
                          </span>
                          <span class="score-details">
                            ({{ notification.metadata.previousScore }} → {{ notification.metadata.currentScore }})
                          </span>
                        </div>
                        <p class="notification-time">{{ formatRelativeTime(notification.createdAt) }}</p>
                      </div>
                      <button
                        @click.stop="deleteNotification(notification.id)"
                        class="notification-delete"
                        title="Delete notification"
                      >
                        <X class="delete-icon" />
                      </button>
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
          <span class="material-symbols-outlined app-picker-icon" aria-hidden="true">apps</span>
        </button>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { useRouter } from 'vue-router';
import { Shield, Search, X, FileText, ShieldCheck, FileCode, RefreshCw, Settings, Menu, Bell, AlertTriangle, TrendingDown, ShieldAlert, CheckCircle, XCircle } from 'lucide-vue-next';
import { useNotifications } from '../composables/useNotifications';
import { NotificationType } from '../types/notification';

const router = useRouter();

const searchQuery = ref('');
const showSearchResults = ref(false);
const isRefreshing = ref(false);
const showSettings = ref(false);
const drawerOpen = ref(false);
const showNotifications = ref(false);
const notificationTab = ref<'all' | 'score-drops' | 'findings' | 'approvals'>('all');
const notificationsContainer = ref<HTMLElement | null>(null);

// Use notifications composable
const {
  notifications,
  unreadCount,
  loading: notificationsLoading,
  loadNotifications,
  markAsRead,
  markAllAsRead,
  deleteNotification,
} = useNotifications();

// Filter notifications by type
const scoreDropNotifications = computed(() => 
  notifications.value.filter(n => n.type === NotificationType.SCORE_DROP)
);

const criticalFindingNotifications = computed(() => 
  notifications.value.filter(n => n.type === NotificationType.CRITICAL_FINDING)
);

const approvalNotifications = computed(() => 
  notifications.value.filter(n => 
    n.type === NotificationType.APPROVAL_REQUEST || 
    n.type === NotificationType.APPROVAL_STATUS_CHANGED
  )
);

const filteredNotifications = computed(() => {
  if (notificationTab.value === 'all') {
    return notifications.value;
  } else if (notificationTab.value === 'score-drops') {
    return scoreDropNotifications.value;
  } else if (notificationTab.value === 'findings') {
    return criticalFindingNotifications.value;
  } else if (notificationTab.value === 'approvals') {
    return approvalNotifications.value;
  }
  return [];
});

const totalNotificationCount = computed(() => unreadCount.value);

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

const handleNotificationClick = async (notification: any) => {
  // Mark as read
  if (!notification.read) {
    await markAsRead(notification.id);
  }

  // Navigate based on notification type
  if (notification.metadata?.findingId) {
    // Navigate to findings page with findingId query param to auto-open modal
    router.push({
      path: '/findings',
      query: { findingId: notification.metadata.findingId }
    });
  } else if (notification.metadata?.approvalRequestId) {
    router.push('/pending-approvals');
  } else if (notification.type === NotificationType.SCORE_DROP) {
    router.push('/developer-findings');
  } else if (notification.type === NotificationType.CRITICAL_FINDING) {
    // Critical findings also have findingId in metadata
    if (notification.metadata?.findingId) {
      router.push({
        path: '/findings',
        query: { findingId: notification.metadata.findingId }
      });
    } else {
      router.push('/findings');
    }
  } else {
    // Default to findings page
    router.push('/findings');
  }

  closeNotifications();
};

const formatRelativeTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
};

const getNotificationIcon = (type: NotificationType) => {
  switch (type) {
    case NotificationType.SCORE_DROP:
      return TrendingDown;
    case NotificationType.CRITICAL_FINDING:
      return ShieldAlert;
    case NotificationType.APPROVAL_REQUEST:
      return AlertTriangle;
    case NotificationType.APPROVAL_STATUS_CHANGED:
      return CheckCircle;
    default:
      return Bell;
  }
};

const getNotificationIconClass = (type: NotificationType): string => {
  switch (type) {
    case NotificationType.SCORE_DROP:
      return 'score-drop-icon';
    case NotificationType.CRITICAL_FINDING:
      return 'critical-icon';
    case NotificationType.APPROVAL_REQUEST:
      return 'approval-icon';
    case NotificationType.APPROVAL_STATUS_CHANGED:
      return 'status-icon';
    default:
      return 'default-icon';
  }
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
  z-index: var(--z-index-nav);
  background: var(--gradient-card);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  box-shadow: var(--shadow-sm);
}

.nav-container {
  display: flex;
  align-items: center;
  height: calc(var(--spacing-2xl) + var(--spacing-md)); /* 64px */
  max-width: 1600px;
  margin: 0 auto;
  padding: 0 var(--spacing-lg);
  gap: var(--spacing-lg);
}

.nav-left {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
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
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
}

.menu-button:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
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
  gap: var(--spacing-sm);
  text-decoration: none;
  transition: opacity var(--transition-base);
}

.logo-link:hover {
  opacity: 0.8;
}

.logo-icon {
  width: 32px;
  height: 32px;
  color: var(--color-primary);
  stroke-width: 2;
}

.logo-text {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  background: var(--gradient-primary);
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
  padding-top: 10px !important;
  padding-right: 40px !important;
  padding-bottom: 10px !important;
  padding-left: 50px !important;
  text-indent: 0;
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  box-sizing: border-box;
}

.search-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
  background: var(--color-bg-overlay-dark);
}

.search-input::placeholder {
  color: var(--color-text-muted);
}

.search-icon {
  position: absolute;
  left: var(--spacing-sm);
  top: 50%;
  transform: translateY(-50%);
  width: 18px;
  height: 18px;
  color: var(--color-text-muted);
  pointer-events: none;
  z-index: 2;
}

.clear-button {
  position: absolute;
  right: var(--spacing-sm);
  top: 50%;
  transform: translateY(-50%);
  padding: var(--spacing-xs);
  background: transparent;
  border: none;
  cursor: pointer;
  color: var(--color-text-muted);
  transition: var(--transition-base);
  display: flex;
  align-items: center;
  justify-content: center;
}

.clear-button:hover {
  color: var(--color-text-primary);
}

.clear-icon {
  width: 16px;
  height: 16px;
}

.search-results {
  position: absolute;
  top: calc(100% + var(--spacing-sm));
  left: 0;
  right: 0;
  max-height: 400px;
  overflow-y: auto;
  background: var(--gradient-card-alt);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  box-shadow: var(--shadow-md);
  z-index: var(--z-index-dropdown);
}

.search-empty {
  padding: var(--spacing-2xl);
  text-align: center;
  color: var(--color-text-muted);
}

.empty-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.search-results-list {
  padding: var(--spacing-sm);
}

.search-result-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  border-radius: var(--border-radius-md);
  cursor: pointer;
  transition: var(--transition-base);
}

.search-result-item:hover {
  background: var(--border-color-muted);
}

.result-icon {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--border-color-muted);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  flex-shrink: 0;
}

.result-content {
  flex: 1;
  min-width: 0;
}

.result-content h4 {
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  margin: 0 0 var(--spacing-xs) 0;
}

.result-content p {
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nav-right {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
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
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
}

.nav-button:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.nav-icon {
  width: 20px;
  height: 20px;
  color: inherit;
}

.app-picker {
  color: var(--color-text-primary);
}

.app-picker:hover {
  background-color: var(--border-color-muted);
  color: var(--color-primary);
}

.app-picker-icon {
  font-size: var(--font-size-2xl);
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  color: var(--color-text-primary);
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
  background: var(--border-color-muted);
}

.avatar-circle {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: var(--gradient-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-bg-primary);
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-sm);
}

.notification-button {
  position: relative;
}

.notification-badge {
  position: absolute;
  top: var(--spacing-xs);
  right: var(--spacing-xs);
  min-width: 18px;
  height: 18px;
  border-radius: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  padding: 0 var(--spacing-xs);
}

.badge-normal {
  background: var(--color-primary);
  color: var(--color-bg-primary);
}

.badge-critical {
  background: var(--color-error);
  color: var(--color-text-primary);
}

.notification-dropdown {
  position: absolute;
  right: 0;
  top: calc(100% + var(--spacing-sm));
  width: 384px;
  max-height: 600px;
  overflow: hidden;
  border-radius: var(--border-radius-lg);
  box-shadow: var(--shadow-xl);
  border: var(--border-width-thin) solid var(--border-color-primary);
  background: var(--gradient-card);
  z-index: var(--z-index-dropdown);
}

.notification-header {
  padding: var(--spacing-md) var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.notification-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.notification-close {
  padding: var(--spacing-xs);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.notification-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 18px;
  height: 18px;
}

.notification-tabs {
  display: flex;
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.notification-tab {
  flex: 1;
  padding: var(--spacing-sm) var(--spacing-md);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--spacing-sm);
}

.notification-tab:hover {
  color: var(--color-primary);
}

.notification-tab.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.tab-badge {
  padding: var(--spacing-xs) var(--spacing-xs);
  border-radius: 10px;
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.tab-badge-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.notification-list {
  overflow-y: auto;
  max-height: 500px;
}

.notification-empty {
  padding: var(--spacing-2xl) var(--spacing-xl);
  text-align: center;
}

.notification-empty .empty-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto var(--spacing-md);
  color: var(--color-text-muted);
  opacity: 0.5;
}

.notification-empty p {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin: 0;
}

.notification-item {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  cursor: pointer;
  transition: var(--transition-base);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.notification-item:hover {
  background: var(--border-color-muted);
  opacity: 0.5;
}

.notification-item-unread {
  background: var(--border-color-muted);
  border-left: 4px solid var(--color-primary);
}

.notification-item-critical {
  border-left: 4px solid var(--color-error);
  background: var(--color-error-bg);
  opacity: 0.5;
}

.notification-item-score-drop {
  border-left: 4px solid var(--color-warning);
  background: var(--color-warning-bg);
  opacity: 0.5;
}

.notification-item-breaking {
  border-left: 4px solid var(--color-error);
  background: var(--color-error-bg);
  opacity: 0.5;
}

.notification-icon {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.score-drop-icon {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.critical-icon {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.approval-icon {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.status-icon {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.default-icon {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
}

.notification-icon .icon {
  width: 20px;
  height: 20px;
}

.notification-content {
  flex: 1;
  min-width: 0;
}

.notification-header-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
}

.unread-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--color-primary);
  flex-shrink: 0;
}

.notification-meta {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.score-change {
  font-weight: var(--font-weight-semibold);
}

.score-change.negative {
  color: var(--color-error);
}

.score-change.positive {
  color: var(--color-success);
}

.score-details {
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
}

.notification-delete {
  padding: var(--spacing-xs);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-xs);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  flex-shrink: 0;
  opacity: 0;
}

.notification-item:hover .notification-delete {
  opacity: 1;
}

.notification-delete:hover {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.delete-icon {
  width: 16px;
  height: 16px;
}

.notification-loading {
  padding: var(--spacing-2xl) var(--spacing-xl);
  text-align: center;
  color: var(--color-text-secondary);
}

.notification-actions {
  padding: var(--spacing-sm) var(--spacing-xl);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.mark-all-read-btn {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.mark-all-read-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.breaking-icon {
  background: var(--color-error-bg);
}

.breaking-icon .icon {
  width: 16px;
  height: 16px;
  color: var(--color-error);
}

.activity-icon {
  background: var(--color-info-bg);
}

.activity-icon .icon {
  width: 16px;
  height: 16px;
  color: var(--color-primary);
}

.notification-content {
  flex: 1;
  min-width: 0;
}

.notification-header-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: 4px;
}

.notification-header-item h4 {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.notification-tag {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.breaking-tag {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.notification-message {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0;
  line-height: 1.4;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.notification-time {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin: 0;
}

/* Responsive - Mobile */
@media (max-width: 639px) {
  .logo-text {
    display: none;
  }
  
  .nav-container {
    padding: 0 12px;
    gap: var(--spacing-sm);
    height: 56px;
  }
  
  .nav-center {
    flex: 1;
    min-width: 0;
  }
  
  .search-container {
    max-width: none;
  }
  
  .search-input {
    font-size: var(--font-size-sm);
    padding: var(--spacing-sm) var(--spacing-2xl) var(--spacing-sm) var(--spacing-2xl) !important;
  }
  
  .nav-right {
    gap: var(--spacing-sm);
  }
  
  .nav-button,
  .user-avatar {
    width: 36px;
    height: 36px;
  }
  
  .notification-dropdown {
    width: calc(100vw - 24px);
    max-width: 384px;
    right: 12px;
  }
  
  .app-picker {
    display: none; /* Hide app picker on mobile to save space */
  }
}

/* Responsive - Tablet */
@media (min-width: 640px) and (max-width: 1023px) {
  .nav-container {
    padding: 0 var(--spacing-lg);
    gap: var(--spacing-md);
  }
  
  .search-container {
    max-width: 500px;
  }
  
  .notification-dropdown {
    width: 360px;
  }
  
  .app-picker {
    display: none; /* Hide app picker on tablet */
  }
}

/* Responsive - Small mobile */
@media (max-width: 374px) {
  .nav-container {
    padding: 0 8px;
    gap: var(--spacing-xs);
  }
  
  .search-input {
    font-size: var(--font-size-xs);
    padding: var(--spacing-xs) var(--spacing-xl) var(--spacing-xs) var(--spacing-lg) !important;
  }
  
  .nav-button,
  .user-avatar {
    width: 32px;
    height: 32px;
  }
  
  .nav-icon {
    width: 18px;
    height: 18px;
  }
}
</style>

