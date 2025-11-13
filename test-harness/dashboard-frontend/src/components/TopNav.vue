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
  padding-top: 10px !important;
  padding-right: 40px !important;
  padding-bottom: 10px !important;
  padding-left: 50px !important;
  text-indent: 0;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  box-sizing: border-box;
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
  z-index: 2;
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
  color: #e3e3e3;
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
  font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  color: #e3e3e3;
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

.notification-item-unread {
  background: rgba(79, 172, 254, 0.1);
  border-left: 4px solid #4facfe;
}

.notification-item-critical {
  border-left: 4px solid #fc8181;
  background: rgba(252, 129, 129, 0.05);
}

.notification-item-score-drop {
  border-left: 4px solid #fbbf24;
  background: rgba(251, 191, 36, 0.05);
}

.notification-item-breaking {
  border-left: 4px solid #fc8181;
  background: rgba(252, 129, 129, 0.05);
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
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.critical-icon {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.approval-icon {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.status-icon {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.default-icon {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
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
  background: #4facfe;
  flex-shrink: 0;
}

.notification-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
  font-size: 0.875rem;
}

.score-change {
  font-weight: 600;
}

.score-change.negative {
  color: #fc8181;
}

.score-change.positive {
  color: #22c55e;
}

.score-details {
  color: #a0aec0;
  font-size: 0.75rem;
}

.notification-delete {
  padding: 4px;
  background: transparent;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  flex-shrink: 0;
  opacity: 0;
}

.notification-item:hover .notification-delete {
  opacity: 1;
}

.notification-delete:hover {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.delete-icon {
  width: 16px;
  height: 16px;
}

.notification-loading {
  padding: 40px 20px;
  text-align: center;
  color: #a0aec0;
}

.notification-actions {
  padding: 12px 20px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.mark-all-read-btn {
  width: 100%;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.mark-all-read-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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
    padding: 8px 36px 8px 44px !important;
  }
}
</style>

