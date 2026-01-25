<template>
  <div class="realtime-monitoring">
    <!-- Connection Status -->
    <div class="connection-status">
      <div class="status-indicator" :class="{ connected: isConnected, disconnected: !isConnected }">
        <div class="status-dot"></div>
        <span class="status-text">
          {{ isConnected ? 'Connected' : isConnecting ? 'Connecting...' : 'Disconnected' }}
        </span>
      </div>
      <div v-if="error" class="error-message">
        <AlertTriangle class="error-icon" />
        {{ error.message }}
      </div>
    </div>

    <!-- Statistics -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Events</div>
        <div class="stat-value">{{ totalEvents }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Findings Today</div>
        <div class="stat-value">{{ findingsToday }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Critical Alerts</div>
        <div class="stat-value critical">{{ criticalAlerts }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Last Update</div>
        <div class="stat-value small">{{ lastUpdateTime || 'Never' }}</div>
      </div>
    </div>

    <!-- Recent Events -->
    <div class="events-section">
      <div class="section-header">
        <h3 class="section-title">Recent Access Events</h3>
        <button @click="clearEvents" class="btn-secondary small" :disabled="recentEvents.length === 0">
          Clear
        </button>
      </div>
      <div v-if="recentEvents.length === 0" class="empty-state">
        <p>No events received yet. Events will appear here in real-time.</p>
      </div>
      <div v-else class="events-list">
        <div
          v-for="event in recentEvents"
          :key="event.id"
          class="event-item"
          :class="`severity-${event.severity}`"
        >
          <div class="event-header">
            <div class="event-type">
              <component :is="getEventIcon(event.type)" class="event-icon" />
              <span class="event-type-text">{{ formatEventType(event.type) }}</span>
            </div>
            <span class="event-time">{{ formatTime(event.timestamp) }}</span>
          </div>
          <div class="event-content">
            <div class="event-title">{{ event.title }}</div>
            <div v-if="event.description" class="event-description">{{ event.description }}</div>
            <div class="event-meta">
              <span v-if="event.applicationId" class="meta-item">
                App: {{ event.applicationName || event.applicationId }}
              </span>
              <span v-if="event.severity" class="meta-item severity-badge" :class="`severity-${event.severity}`">
                {{ event.severity }}
              </span>
              <span v-if="event.riskScore !== undefined" class="meta-item">
                Risk: {{ event.riskScore }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Anomaly Alerts -->
    <div v-if="anomalyAlerts.length > 0" class="anomalies-section">
      <div class="section-header">
        <h3 class="section-title">
          <AlertTriangle class="section-icon" />
          Anomaly Alerts
        </h3>
      </div>
      <div class="anomalies-list">
        <div
          v-for="alert in anomalyAlerts"
          :key="alert.id"
          class="anomaly-alert"
          :class="`severity-${alert.severity}`"
        >
          <div class="alert-header">
            <AlertTriangle class="alert-icon" />
            <span class="alert-title">{{ alert.title }}</span>
            <span class="alert-time">{{ formatTime(alert.timestamp) }}</span>
          </div>
          <div class="alert-description">{{ alert.description }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { useRealtimeUpdates, DashboardUpdate } from '../composables/useRealtimeUpdates';
import { AlertTriangle, Activity, Shield, Zap, Clock } from 'lucide-vue-next';

interface RealtimeEvent {
  id: string;
  type: string;
  title: string;
  description?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  timestamp: Date;
  applicationId?: string;
  applicationName?: string;
  riskScore?: number;
}

interface AnomalyAlert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
}

const props = defineProps<{
  applicationId?: string;
  maxEvents?: number;
}>();

const maxEventsToShow = props.maxEvents || 50;
const recentEvents = ref<RealtimeEvent[]>([]);
const anomalyAlerts = ref<AnomalyAlert[]>([]);
const totalEvents = ref(0);
const findingsToday = ref(0);
const criticalAlerts = ref(0);
const lastUpdateTime = ref<string | null>(null);

const { isConnected, isConnecting, error } = useRealtimeUpdates({
  filters: props.applicationId ? { applicationId: props.applicationId } : undefined,
  onUpdate: (update: DashboardUpdate) => {
    handleUpdate(update);
  },
  onError: (err: Error) => {
    console.error('Real-time update error:', err);
  },
});

const handleUpdate = (update: DashboardUpdate) => {
  totalEvents.value++;
  lastUpdateTime.value = new Date().toLocaleTimeString();

  // Handle violation/finding updates
  if (update.type === 'violation' && update.data?.finding) {
    const finding = update.data.finding;
    const event: RealtimeEvent = {
      id: finding.id || `event-${Date.now()}-${Math.random()}`,
      type: update.data.eventType || 'finding',
      title: finding.title || 'Security Finding',
      description: finding.description,
      severity: finding.severity,
      timestamp: new Date(update.timestamp),
      applicationId: finding.asset?.applicationId || update.data.applicationId,
      applicationName: update.data.applicationName,
      riskScore: finding.riskScore,
    };

    // Add to recent events
    recentEvents.value.unshift(event);
    if (recentEvents.value.length > maxEventsToShow) {
      recentEvents.value.pop();
    }

    // Update counters
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (new Date(event.timestamp) >= today) {
      findingsToday.value++;
    }

    if (event.severity === 'critical') {
      criticalAlerts.value++;
      // Add to anomaly alerts
      anomalyAlerts.value.unshift({
        id: event.id,
        title: `Critical Finding: ${event.title}`,
        description: event.description || 'A critical security finding was detected',
        severity: 'critical',
        timestamp: event.timestamp,
      });
      if (anomalyAlerts.value.length > 10) {
        anomalyAlerts.value.pop();
      }
    }
  }

  // Handle notification updates
  if (update.type === 'notification' && update.data?.type === 'error') {
    const alert: AnomalyAlert = {
      id: `alert-${Date.now()}`,
      title: 'Ingestion Error',
      description: update.data.message || 'An error occurred during real-time ingestion',
      severity: 'high',
      timestamp: new Date(update.timestamp),
    };
    anomalyAlerts.value.unshift(alert);
    if (anomalyAlerts.value.length > 10) {
      anomalyAlerts.value.pop();
    }
  }
};

const clearEvents = () => {
  recentEvents.value = [];
  findingsToday.value = 0;
  criticalAlerts.value = 0;
};

const formatEventType = (type: string): string => {
  const typeMap: Record<string, string> = {
    finding_normalized: 'Finding Normalized',
    finding_scored: 'Finding Scored',
    finding_received: 'Finding Received',
    violation: 'Violation',
    notification: 'Notification',
  };
  return typeMap[type] || type;
};

const getEventIcon = (type: string) => {
  const iconMap: Record<string, any> = {
    finding_normalized: Shield,
    finding_scored: Activity,
    finding_received: Zap,
    violation: AlertTriangle,
    notification: Clock,
  };
  return iconMap[type] || Activity;
};

const formatTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);

  if (diffSecs < 60) {
    return `${diffSecs}s ago`;
  } else if (diffMins < 60) {
    return `${diffMins}m ago`;
  } else if (diffHours < 24) {
    return `${diffHours}h ago`;
  } else {
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
  }
};

// Initialize counters
onMounted(() => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  findingsToday.value = recentEvents.value.filter(
    e => new Date(e.timestamp) >= today
  ).length;
});
</script>

<style scoped>
.realtime-monitoring {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.connection-status {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem;
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.status-text {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.status-indicator.connected .status-text {
  color: var(--color-success);
}

.status-indicator.disconnected .status-text {
  color: var(--color-error);
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--color-text-muted);
  animation: pulse 2s infinite;
}

.status-indicator.connected .status-dot {
  background: var(--color-success);
}

.status-indicator.disconnected .status-dot {
  background: var(--color-error);
  animation: none;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.error-message {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--color-error);
  font-size: var(--font-size-sm);
}

.error-icon {
  width: 16px;
  height: 16px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
}

.stat-card {
  padding: 1rem;
  background: var(--color-bg-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: 0.5rem;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.stat-value.critical {
  color: var(--color-error);
}

.stat-value.small {
  font-size: var(--font-size-sm);
}

.events-section,
.anomalies-section {
  background: var(--color-bg-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: 1.5rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.section-icon {
  width: 20px;
  height: 20px;
  color: var(--color-text-secondary);
}

.events-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-height: 600px;
  overflow-y: auto;
}

.event-item {
  padding: 1rem;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  border-left: 4px solid var(--color-text-muted);
  background: var(--color-bg-secondary);
  transition: var(--transition-all);
}

.event-item:hover {
  background: var(--color-bg-tertiary);
  border-color: var(--border-color-primary-hover);
}

.event-item.severity-critical {
  border-left-color: var(--color-error);
  background: var(--color-error-bg);
}

.event-item.severity-high {
  border-left-color: var(--color-warning);
  background: var(--color-warning-bg);
}

.event-item.severity-medium {
  border-left-color: var(--color-info);
  background: var(--color-info-bg);
}

.event-item.severity-low {
  border-left-color: var(--color-success);
  background: var(--color-success-bg);
}

.event-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.event-type {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.event-type-text {
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.event-icon {
  width: 16px;
  height: 16px;
  color: var(--color-text-secondary);
}

.event-time {
  color: var(--color-text-muted);
  font-size: var(--font-size-xs);
}

.event-title {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: 0.25rem;
}

.event-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: 0.5rem;
}

.event-meta {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.meta-item {
  color: var(--color-text-secondary);
}

.severity-badge {
  padding: 0.25rem 0.5rem;
  border-radius: var(--border-radius-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: uppercase;
  font-size: var(--font-size-xs);
}

.severity-badge.severity-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.severity-badge.severity-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.severity-badge.severity-medium {
  background: var(--color-info-bg);
  color: var(--color-info);
}

.severity-badge.severity-low {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.anomalies-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.anomaly-alert {
  padding: 1rem;
  border-radius: var(--border-radius-sm);
  border-left: 4px solid var(--color-error);
  background: var(--color-error-bg);
}

.alert-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.alert-icon {
  width: 20px;
  height: 20px;
  color: var(--color-error);
}

.alert-title {
  font-weight: var(--font-weight-semibold);
  color: var(--color-error);
  flex: 1;
}

.alert-time {
  color: var(--color-text-muted);
  font-size: var(--font-size-xs);
}

.alert-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.empty-state {
  padding: 2rem;
  text-align: center;
  color: var(--color-text-muted);
}

.btn-secondary.small {
  padding: 0.375rem 0.75rem;
  font-size: var(--font-size-sm);
}
</style>
