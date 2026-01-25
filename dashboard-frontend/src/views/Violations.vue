<template>
  <div class="violations-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Violations</h1>
          <p class="page-description">View and manage access control violations</p>
        </div>
        <div class="header-stats">
          <div class="stat-card critical">
            <span class="stat-label">Critical</span>
            <span class="stat-value">{{ criticalCount }}</span>
          </div>
          <div class="stat-card open">
            <span class="stat-label">Open</span>
            <span class="stat-value">{{ openCount }}</span>
          </div>
          <div class="stat-card resolved">
            <span class="stat-label">Resolved</span>
            <span class="stat-value">{{ resolvedCount }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Filters and Sort -->
    <div class="filters-section">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search violations..."
          class="search-input"
        />
        <Dropdown
          v-model="filters.severity"
          :options="severityOptions"
          placeholder="All Severities"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filters.type"
          :options="typeOptions"
          placeholder="All Types"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filters.status"
          :options="statusOptions"
          placeholder="All Statuses"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filters.application"
          :options="applicationOptions"
          placeholder="All Applications"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filters.team"
          :options="teamOptions"
          placeholder="All Teams"
          class="filter-dropdown"
        />
      </div>
      <div class="sort-section">
        <label class="sort-label">Sort by:</label>
        <Dropdown
          v-model="sortBy"
          :options="sortOptions"
          placeholder="Date"
          class="sort-dropdown"
        />
        <button
          @click="sortOrder = sortOrder === 'asc' ? 'desc' : 'asc'"
          class="sort-order-btn"
          :class="{ 'desc': sortOrder === 'desc' }"
        >
          <ArrowUpDown class="sort-icon" />
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="loading-state">
      <p>Loading violations...</p>
    </div>

    <!-- Violations List -->
    <div v-else class="violations-list">
      <div
        v-for="violation in sortedViolations"
        :key="violation.id"
        class="violation-card"
        :class="`severity-${violation.severity}`"
        @click="viewViolation(violation.id)"
      >
        <div class="violation-header">
          <div class="violation-title-row">
            <div class="violation-title-group">
              <AlertTriangle class="violation-icon" :class="`icon-${violation.severity}`" />
              <h3 class="violation-title">{{ violation.title }}</h3>
            </div>
            <div class="violation-badges">
              <span class="severity-badge" :class="`badge-${violation.severity}`">
                {{ violation.severity }}
              </span>
              <span class="status-badge" :class="`status-${violation.status}`">
                {{ violation.status }}
              </span>
            </div>
          </div>
          <p class="violation-meta">
            <span v-if="violation.application">{{ violation.application }}</span>
            <span v-if="violation.application && violation.team"> • </span>
            <span v-if="violation.team">{{ violation.team }}</span>
            <span v-if="(violation.application || violation.team) && violation.detectedAt"> • </span>
            <span v-if="violation.detectedAt">{{ formatDate(violation.detectedAt) }}</span>
          </p>
        </div>

        <p class="violation-description">{{ violation.description }}</p>

        <div class="violation-details">
          <div class="detail-item" v-if="violation.type">
            <span class="detail-label">Type:</span>
            <span class="detail-value">{{ formatType(violation.type) }}</span>
          </div>
          <div class="detail-item" v-if="violation.policyName">
            <span class="detail-label">Policy:</span>
            <span class="detail-value">{{ violation.policyName }}</span>
          </div>
          <div class="detail-item" v-if="violation.resource">
            <span class="detail-label">Resource:</span>
            <span class="detail-value">{{ violation.resource }}</span>
          </div>
        </div>

        <div class="violation-actions">
          <button @click.stop="assignViolation(violation.id)" class="action-btn assign-btn">
            <User class="action-icon" />
            Assign
          </button>
          <button @click.stop="resolveViolation(violation.id)" class="action-btn resolve-btn" v-if="violation.status !== 'resolved'">
            <CheckCircle2 class="action-icon" />
            Resolve
          </button>
          <button @click.stop="ignoreViolation(violation.id)" class="action-btn ignore-btn" v-if="violation.status !== 'ignored'">
            <X class="action-icon" />
            Ignore
          </button>
        </div>
      </div>
    </div>

    <div v-if="!loading && sortedViolations.length === 0" class="empty-state">
      <CheckCircle2 class="empty-icon" />
      <h3>No violations found</h3>
      <p>All access control policies are being followed</p>
    </div>

    <!-- Violation Detail Modal -->
    <ViolationDetailModal
      :show="violationModal.isOpen.value"
      :violation="violationModal.data.value"
      @close="violationModal.close()"
      @update="handleViolationUpdate"
      @viewRelated="viewRelatedViolation"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import {
  AlertTriangle,
  CheckCircle2,
  X,
  User,
  ArrowUpDown
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ViolationDetailModal from '../components/ViolationDetailModal.vue';
import type { ViolationEntity } from '../types/violation';
import { useApiDataAuto } from '../composables/useApiData';
import { useSearch } from '../composables/useFilters';
import { useFilters } from '../composables/useFilters';
import { useModal } from '../composables/useModal';
import { useAuth } from '../composables/useAuth';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Violations' }
];

const API_BASE_URL = '/api';

// Use composable for API data fetching
const { data: violations, loading, reload: loadViolations } = useApiDataAuto(
  async () => {
    const params = new URLSearchParams();
    const response = await fetch(`${API_BASE_URL}/violations?${params.toString()}`);
    if (!response.ok) throw new Error('Failed to load violations');
    const data = await response.json();
    return data.map((v: any) => ({
      ...v,
      detectedAt: new Date(v.detectedAt),
      resolvedAt: v.resolvedAt ? new Date(v.resolvedAt) : undefined,
      ignoredAt: v.ignoredAt ? new Date(v.ignoredAt) : undefined,
      createdAt: new Date(v.createdAt),
      updatedAt: new Date(v.updatedAt),
    }));
  },
  {
    initialData: [],
    errorMessage: 'Failed to load violations',
  }
);

// Use composable for search
const searchQuery = ref('');
const { filteredItems: searchFilteredViolations } = useSearch(
  violations,
  ['title', 'description'],
  searchQuery
);

// Use composable for filters
const filters = ref({
  severity: '',
  type: '',
  status: '',
  application: '',
  team: '',
});

const { filteredItems: filteredViolations } = useFilters(
  searchFilteredViolations,
  (violation, filters) => {
    const matchesSeverity = !filters.severity || violation.severity === filters.severity;
    const matchesType = !filters.type || violation.type === filters.type;
    const matchesStatus = !filters.status || violation.status === filters.status;
    const matchesApp = !filters.application || violation.application === filters.application;
    const matchesTeam = !filters.team || violation.team === filters.team;
    return matchesSeverity && matchesType && matchesStatus && matchesApp && matchesTeam;
  },
  filters
);

const sortBy = ref('date');
const sortOrder = ref<'asc' | 'desc'>('desc');

// Use composable for modal state
const violationModal = useModal<ViolationEntity>();

// Get current user from auth context
const { user } = useAuth();

const severityOptions = computed(() => [
  { label: 'All Severities', value: '' },
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' }
]);

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'Access Control', value: 'access-control' },
  { label: 'Contract', value: 'contract' },
  { label: 'Dataset Health', value: 'dataset-health' },
  { label: 'API Security', value: 'api-security' },
  { label: 'Pipeline', value: 'pipeline' },
  { label: 'Distributed System', value: 'distributed-system' }
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Open', value: 'open' },
  { label: 'In Progress', value: 'in-progress' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'Ignored', value: 'ignored' }
]);

const sortOptions = computed(() => [
  { label: 'Date', value: 'date' },
  { label: 'Severity', value: 'severity' },
  { label: 'Application', value: 'application' },
  { label: 'Status', value: 'status' }
]);

const applications = computed(() => {
  return [...new Set(violations.value.map(v => v.application).filter(Boolean))];
});

const teams = computed(() => {
  return [...new Set(violations.value.map(v => v.team).filter(Boolean))];
});

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app, value: app }))
  ];
});

const teamOptions = computed(() => {
  return [
    { label: 'All Teams', value: '' },
    ...teams.value.map(team => ({ label: team, value: team }))
  ];
});

const criticalCount = computed(() => {
  return (violations.value || []).filter(v => v.severity === 'critical' && v.status !== 'resolved').length;
});

const openCount = computed(() => {
  return (violations.value || []).filter(v => v.status === 'open').length;
});

const resolvedCount = computed(() => {
  return (violations.value || []).filter(v => v.status === 'resolved').length;
});

const sortedViolations = computed(() => {
  const sorted = [...(filteredViolations.value || [])];
  
  sorted.sort((a, b) => {
    let comparison = 0;
    
    switch (sortBy.value) {
      case 'date':
        comparison = new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime();
        break;
      case 'severity':
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        comparison = (severityOrder[a.severity as keyof typeof severityOrder] || 0) -
                     (severityOrder[b.severity as keyof typeof severityOrder] || 0);
        break;
      case 'application':
        comparison = (a.application || '').localeCompare(b.application || '');
        break;
      case 'status':
        const statusOrder = { open: 1, 'in-progress': 2, resolved: 3, ignored: 4 };
        comparison = (statusOrder[a.status as keyof typeof statusOrder] || 0) -
                     (statusOrder[b.status as keyof typeof statusOrder] || 0);
        break;
    }
    
    return sortOrder.value === 'asc' ? comparison : -comparison;
  });
  
  return sorted;
});

const viewViolation = async (id: string) => {
  try {
    const response = await fetch(`${API_BASE_URL}/violations/${id}`);
    if (response.ok) {
      const violation = await response.json();
      const formattedViolation = {
        ...violation,
        detectedAt: new Date(violation.detectedAt),
        resolvedAt: violation.resolvedAt ? new Date(violation.resolvedAt) : undefined,
        ignoredAt: violation.ignoredAt ? new Date(violation.ignoredAt) : undefined,
        createdAt: new Date(violation.createdAt),
        updatedAt: new Date(violation.updatedAt),
      };
      violationModal.open(formattedViolation);
    }
  } catch (error) {
    console.error('Error loading violation:', error);
  }
};

const handleViolationUpdate = (updatedViolation: ViolationEntity) => {
  if (violations.value) {
    const index = violations.value.findIndex(v => v.id === updatedViolation.id);
    if (index !== -1) {
      violations.value[index] = updatedViolation;
    }
  }
  if (violationModal.data.value?.id === updatedViolation.id) {
    violationModal.open(updatedViolation);
  }
};

const viewRelatedViolation = (id: string) => {
  violationModal.close();
  viewViolation(id);
};

const assignViolation = async (id: string) => {
  const violation = (violations.value || []).find(v => v.id === id);
  if (!violation) return;
  
  const assignee = prompt('Enter assignee email:', violation.assignedTo || '');
  if (assignee === null) return;

  try {
    const response = await fetch(`${API_BASE_URL}/violations/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        assignedTo: assignee || null,
        status: assignee ? 'in-progress' : violation.status,
      }),
    });

    if (response.ok) {
      await loadViolations();
    }
  } catch (error) {
    console.error('Error assigning violation:', error);
  }
};

const resolveViolation = async (id: string) => {
  if (!confirm('Mark this violation as resolved?')) return;

  try {
    const response = await fetch(`${API_BASE_URL}/violations/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'resolved',
        resolvedAt: new Date().toISOString(),
        resolvedBy: user.value.email,
      }),
    });

    if (response.ok) {
      await loadViolations();
    }
  } catch (error) {
    console.error('Error resolving violation:', error);
  }
};

const ignoreViolation = async (id: string) => {
  if (!confirm('Ignore this violation? It will be marked as ignored.')) return;

  try {
    const response = await fetch(`${API_BASE_URL}/violations/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'ignored',
        ignoredAt: new Date().toISOString(),
        ignoredBy: user.value.email,
      }),
    });

    if (response.ok) {
      await loadViolations();
    }
  } catch (error) {
    console.error('Error ignoring violation:', error);
  }
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
};

const formatType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

// Note: useApiDataAuto automatically loads on mount, and filters/search are handled by composables
</script>

<style scoped>
.violations-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
  flex-wrap: wrap;
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.header-stats {
  display: flex;
  gap: var(--spacing-md);
}

.stat-card {
  padding: var(--spacing-md) var(--spacing-lg);
  border-radius: var(--border-radius-lg);
  border: var(--border-width-thin) solid;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  min-width: 120px;
}

.stat-card.critical {
  background: var(--color-error-bg);
  border-color: var(--color-error);
  opacity: 0.3;
}

.stat-card.open {
  background: var(--color-warning-bg);
  border-color: var(--color-warning);
  opacity: 0.3;
}

.stat-card.resolved {
  background: var(--color-success-bg);
  border-color: var(--color-success);
  opacity: 0.3;
}

.stat-label {
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
  text-transform: uppercase;
}

.stat-card.critical .stat-label {
  color: var(--color-error);
}

.stat-card.open .stat-label {
  color: var(--color-warning);
}

.stat-card.resolved .stat-label {
  color: var(--color-success);
}

.stat-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.filters-section {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
  flex-wrap: wrap;
}

.filters {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
  flex: 1;
}

.search-input {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
  min-width: 200px;
  flex: 1;
}

.filter-dropdown {
  min-width: 150px;
}

.search-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.sort-section {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.sort-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
}

.sort-dropdown {
  min-width: 120px;
}

.sort-order-btn {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  cursor: pointer;
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.sort-order-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.sort-order-btn.desc .sort-icon {
  transform: rotate(180deg);
}

.sort-icon {
  width: 18px;
  height: 18px;
  transition: transform 0.2s;
}

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.violations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.violation-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left: 4px solid;
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.violation-card.severity-critical {
  border-left-color: var(--color-error);
  background: linear-gradient(135deg, var(--color-error-bg) 0%, var(--color-bg-primary) 100%);
}

.violation-card.severity-high {
  border-left-color: var(--color-warning);
}

.violation-card.severity-medium {
  border-left-color: var(--color-primary);
}

.violation-card.severity-low {
  border-left-color: var(--color-text-muted);
}

.violation-card:hover {
  transform: translateX(4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.violation-header {
  margin-bottom: var(--spacing-md);
}

.violation-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
  gap: var(--spacing-md);
}

.violation-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  flex: 1;
}

.violation-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
}

.icon-critical {
  color: var(--color-error);
}

.icon-high {
  color: var(--color-warning);
}

.icon-medium {
  color: var(--color-primary);
}

.icon-low {
  color: var(--color-text-muted);
}

.violation-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.violation-badges {
  display: flex;
  gap: var(--spacing-sm);
  flex-shrink: 0;
}

.severity-badge,
.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.badge-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.badge-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.badge-medium {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.badge-low {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-muted);
}

.status-open {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-in-progress {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.status-resolved {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-ignored {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-muted);
}

.violation-meta {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.violation-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  line-height: 1.5;
  margin-bottom: var(--spacing-md);
}

.violation-details {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.detail-item {
  display: flex;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.detail-label {
  color: var(--color-text-muted);
  font-weight: var(--font-weight-medium);
}

.detail-value {
  color: var(--color-text-primary);
}

.violation-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.assign-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.resolve-btn:hover {
  background: var(--color-success-bg);
  border-color: var(--color-success);
  color: var(--color-success);
}

.ignore-btn:hover {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  border-color: var(--color-text-muted);
  opacity: 0.5;
  color: var(--color-text-muted);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-success);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
}
</style>
