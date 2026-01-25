/**
 * Composable for real-time dashboard updates using Server-Sent Events (SSE)
 */

import { ref, onMounted, onBeforeUnmount } from 'vue';

export interface DashboardUpdate {
  type: 'dashboard' | 'test-result' | 'compliance-score' | 'violation' | 'notification' | 'connected';
  data: any;
  timestamp: string;
  clientId?: string;
}

export interface RealtimeUpdateOptions {
  filters?: {
    applicationId?: string;
    teamId?: string;
  };
  onUpdate?: (update: DashboardUpdate) => void;
  onError?: (error: Error) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  autoReconnect?: boolean;
  reconnectDelay?: number;
}

/**
 * Composable for real-time dashboard updates
 */
export function useRealtimeUpdates(options: RealtimeUpdateOptions = {}) {
  const {
    filters,
    onUpdate,
    onError,
    onConnect,
    onDisconnect,
    autoReconnect = true,
    reconnectDelay = 3000,
  } = options;

  const isConnected = ref(false);
  const isConnecting = ref(false);
  const error = ref<Error | null>(null);
  const eventSource = ref<EventSource | null>(null);
  const reconnectAttempts = ref(0);
  const maxReconnectAttempts = 5;

  const connect = () => {
    if (isConnecting.value || (eventSource.value && eventSource.value.readyState !== EventSource.CLOSED)) {
      return;
    }

    isConnecting.value = true;
    error.value = null;

    try {
      // Build URL with filters
      let url = '/api/v1/dashboard/stream';
      if (filters) {
        const filterParams = new URLSearchParams();
        if (filters.applicationId) {
          filterParams.append('applicationId', filters.applicationId);
        }
        if (filters.teamId) {
          filterParams.append('teamId', filters.teamId);
        }
        if (filterParams.toString()) {
          url += `?filters=${encodeURIComponent(JSON.stringify(filters))}`;
        }
      }

      const es = new EventSource(url);
      eventSource.value = es;

      es.onopen = () => {
        isConnected.value = true;
        isConnecting.value = false;
        reconnectAttempts.value = 0;
        error.value = null;
        if (onConnect) {
          onConnect();
        }
      };

      es.onmessage = (event) => {
        try {
          const update: DashboardUpdate = JSON.parse(event.data);
          
          // Handle connection confirmation
          if (update.type === 'connected') {
            // Connection confirmed - no logging needed in production
            return;
          }

          // Handle heartbeat
          if (event.data.trim() === ': heartbeat') {
            return;
          }

          if (onUpdate) {
            onUpdate(update);
          }
        } catch (err) {
          console.error('Error parsing SSE message:', err);
          if (onError) {
            onError(err as Error);
          }
        }
      };

      es.onerror = (_err) => {
        isConnecting.value = false;
        
        if (es.readyState === EventSource.CLOSED) {
          isConnected.value = false;
          
          if (onDisconnect) {
            onDisconnect();
          }

          // Attempt to reconnect
          if (autoReconnect && reconnectAttempts.value < maxReconnectAttempts) {
            reconnectAttempts.value++;
            const delay = reconnectDelay * reconnectAttempts.value;
            // Reconnection attempt - no logging needed in production
            
            setTimeout(() => {
              connect();
            }, delay);
          } else if (reconnectAttempts.value >= maxReconnectAttempts) {
            const reconnectError = new Error('Max reconnection attempts reached');
            error.value = reconnectError;
            if (onError) {
              onError(reconnectError);
            }
          }
        } else {
          // Connection error
          const connectionError = new Error('SSE connection error');
          error.value = connectionError;
          if (onError) {
            onError(connectionError);
          }
        }
      };
    } catch (err) {
      isConnecting.value = false;
      const connectionError = err instanceof Error ? err : new Error('Failed to create SSE connection');
      error.value = connectionError;
      if (onError) {
        onError(connectionError);
      }
    }
  };

  const disconnect = () => {
    if (eventSource.value) {
      eventSource.value.close();
      eventSource.value = null;
    }
    isConnected.value = false;
    isConnecting.value = false;
    reconnectAttempts.value = 0;
    
    if (onDisconnect) {
      onDisconnect();
    }
  };

  const reconnect = () => {
    disconnect();
    reconnectAttempts.value = 0;
    setTimeout(() => {
      connect();
    }, reconnectDelay);
  };

  onMounted(() => {
    connect();
  });

  onBeforeUnmount(() => {
    disconnect();
  });

  return {
    isConnected,
    isConnecting,
    error,
    connect,
    disconnect,
    reconnect,
  };
}

