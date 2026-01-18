import { ref, onMounted, onBeforeUnmount } from 'vue';
import axios from 'axios';
import { Notification } from '../types/notification';

export function useNotifications() {
  const notifications = ref<Notification[]>([]);
  const unreadCount = ref(0);
  const loading = ref(false);
  const error = ref<string | null>(null);
  let refreshInterval: number | null = null;

  const loadNotifications = async (unreadOnly: boolean = false) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get('/api/v1/notifications', {
        params: { unreadOnly: unreadOnly ? 'true' : undefined },
      });
      notifications.value = response.data.map((n: any) => ({
        ...n,
        createdAt: new Date(n.createdAt),
      }));
    } catch (err: any) {
      // Don't show error to user if it's a network error or 401/403 (auth issues)
      if (err.code === 'ERR_NETWORK' || err.response?.status === 401 || err.response?.status === 403) {
        // Silently fail - user might not be authenticated
        notifications.value = [];
      } else {
        error.value = err.response?.data?.message || 'Failed to load notifications';
        console.error('Failed to load notifications:', err);
      }
    } finally {
      loading.value = false;
    }
  };

  const getUnreadCount = async () => {
    try {
      const response = await axios.get('/api/v1/notifications/unread-count');
      unreadCount.value = response.data.count || 0;
    } catch (err: any) {
      // Silently fail - don't break UI if notification count fails
      if (err.code !== 'ERR_NETWORK' && err.response?.status !== 401 && err.response?.status !== 403) {
        console.error('Failed to get unread count:', err);
      }
      unreadCount.value = 0;
    }
  };

  const markAsRead = async (notificationId: string) => {
    try {
      await axios.patch(`/api/v1/notifications/${notificationId}/read`);
      // Update local state
      const notification = notifications.value.find(n => n.id === notificationId);
      if (notification) {
        notification.read = true;
      }
      await getUnreadCount();
    } catch (err) {
      console.error('Failed to mark notification as read:', err);
    }
  };

  const markAllAsRead = async () => {
    try {
      await axios.patch('/api/v1/notifications/read-all');
      // Update local state
      notifications.value.forEach(n => {
        n.read = true;
      });
      unreadCount.value = 0;
    } catch (err) {
      console.error('Failed to mark all as read:', err);
    }
  };

  const deleteNotification = async (notificationId: string) => {
    try {
      await axios.delete(`/api/v1/notifications/${notificationId}`);
      notifications.value = notifications.value.filter(n => n.id !== notificationId);
      await getUnreadCount();
    } catch (err) {
      console.error('Failed to delete notification:', err);
    }
  };

  const startAutoRefresh = (intervalMs: number = 30000) => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
    }
    refreshInterval = window.setInterval(() => {
      loadNotifications();
      getUnreadCount();
    }, intervalMs);
  };

  const stopAutoRefresh = () => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
      refreshInterval = null;
    }
  };

  // Load on mount
  onMounted(() => {
    loadNotifications();
    getUnreadCount();
    startAutoRefresh();
  });

  // Cleanup on unmount
  onBeforeUnmount(() => {
    stopAutoRefresh();
  });

  return {
    notifications,
    unreadCount,
    loading,
    error,
    loadNotifications,
    getUnreadCount,
    markAsRead,
    markAllAsRead,
    deleteNotification,
    startAutoRefresh,
    stopAutoRefresh,
  };
}

