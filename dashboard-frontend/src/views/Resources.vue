<template>
  <div class="resources-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Resources</h1>
          <p class="page-description">Manage resources and their ABAC attributes</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Resource
        </button>
      </div>
    </div>

    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search resources..."
        class="search-input"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterSensitivity"
        :options="sensitivityOptions"
        placeholder="All Sensitivity Levels"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterApplication"
        :options="applicationOptions"
        placeholder="All Applications"
        class="filter-dropdown"
      />
    </div>

    <div class="resources-grid">
      <div
        v-for="resource in filteredResources"
        :key="resource.id"
        class="resource-card"
        @click="viewResourceDetails(resource.id)"
      >
        <div class="resource-header">
          <div class="resource-title-row">
            <h3 class="resource-name">{{ resource.id }}</h3>
            <span class="resource-sensitivity" :class="`sensitivity-${resource.sensitivity}`">
              {{ resource.sensitivity || 'N/A' }}
            </span>
          </div>
          <div class="resource-meta">
            <span class="resource-type">{{ resource.type }}</span>
            <span class="resource-application" v-if="resource.application">{{ resource.application }}</span>
          </div>
        </div>

        <div class="resource-attributes" v-if="resource.abacAttributes">
          <div class="attributes-preview">
            <div
              v-for="[key, value] in Object.entries(resource.abacAttributes).slice(0, 3)"
              :key="key"
              class="attribute-preview"
            >
              <span class="attr-key">{{ formatKey(key) }}:</span>
              <span class="attr-value">{{ formatValue(value) }}</span>
            </div>
            <span v-if="Object.keys(resource.abacAttributes).length > 3" class="more-attributes">
              +{{ Object.keys(resource.abacAttributes).length - 3 }} more
            </span>
          </div>
        </div>

        <div class="resource-actions">
          <button @click.stop="editResource(resource.id)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click.stop="deleteResource(resource.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredResources.length === 0" class="empty-state">
      <Database class="empty-icon" />
      <h3>No resources found</h3>
      <p>Create your first resource to get started</p>
      <button @click="showCreateModal = true" class="btn-primary">
        Add Resource
      </button>
    </div>

    <!-- Resource Modal -->
    <ResourceModal
      :show="showCreateModal || !!editingResource"
      :resource="editingResourceData"
      @close="closeModal"
      @save="saveResource"
    />

    <!-- Resource Detail Modal -->
    <ResourceDetailModal
      :show="showDetailModal"
      :resource="selectedResource"
      @close="closeDetailModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  Database,
  Plus,
  Edit,
  Trash2
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ResourceModal from '../components/ResourceModal.vue';
import ResourceDetailModal from '../components/ResourceDetailModal.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Resources' }
];

const searchQuery = ref('');
const filterType = ref('');
const filterSensitivity = ref('');
const filterApplication = ref('');
const showCreateModal = ref(false);
const showDetailModal = ref(false);
const editingResource = ref<string | null>(null);
const editingResourceData = ref<any>(null);
const selectedResource = ref<any>(null);

// Resources data
const resources = ref([
  {
    id: 'reports',
    type: 'report',
    application: 'research-tracker-api',
    sensitivity: 'internal',
    attributes: { sensitivity: 'internal' },
    abacAttributes: {
      dataClassification: 'internal',
      department: 'Research',
      project: 'project-alpha'
    }
  },
  {
    id: 'user-data',
    type: 'user',
    application: 'user-service',
    sensitivity: 'confidential',
    attributes: { sensitivity: 'confidential' },
    abacAttributes: {
      dataClassification: 'confidential',
      department: 'IT',
      minClearanceLevel: 'medium'
    }
  },
  {
    id: 'pii-data',
    type: 'pii',
    application: 'data-platform',
    sensitivity: 'restricted',
    attributes: { sensitivity: 'restricted' },
    abacAttributes: {
      dataClassification: 'restricted',
      department: 'Finance',
      minClearanceLevel: 'high',
      requiresCertification: ['data-governance']
    }
  }
]);

const typeOptions = computed(() => {
  const types = [...new Set(resources.value.map(r => r.type))];
  return [
    { label: 'All Types', value: '' },
    ...types.map(type => ({ label: type, value: type }))
  ];
});

const sensitivityOptions = computed(() => [
  { label: 'All Sensitivity Levels', value: '' },
  { label: 'Public', value: 'public' },
  { label: 'Internal', value: 'internal' },
  { label: 'Confidential', value: 'confidential' },
  { label: 'Restricted', value: 'restricted' }
]);

const applicationOptions = computed(() => {
  const apps = [...new Set(resources.value.map(r => r.application).filter(Boolean))];
  return [
    { label: 'All Applications', value: '' },
    ...apps.map(app => ({ label: app, value: app }))
  ];
});

const filteredResources = computed(() => {
  return resources.value.filter(resource => {
    const matchesSearch = resource.id.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         resource.type.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || resource.type === filterType.value;
    const matchesSensitivity = !filterSensitivity.value || resource.sensitivity === filterSensitivity.value;
    const matchesApplication = !filterApplication.value || resource.application === filterApplication.value;
    return matchesSearch && matchesType && matchesSensitivity && matchesApplication;
  });
});

function formatKey(key: string): string {
  return key.split(/(?=[A-Z])/).map(word => 
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ');
}

function formatValue(value: any): string {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  return String(value);
}

function viewResourceDetails(id: string) {
  const resource = resources.value.find(r => r.id === id);
  if (resource) {
    selectedResource.value = resource;
    showDetailModal.value = true;
  }
}

function closeDetailModal() {
  showDetailModal.value = false;
  selectedResource.value = null;
}

function editResource(id: string) {
  const resource = resources.value.find(r => r.id === id);
  if (resource) {
    editingResource.value = id;
    editingResourceData.value = resource;
    showCreateModal.value = true;
  }
}

function deleteResource(id: string) {
  if (confirm('Are you sure you want to delete this resource?')) {
    const index = resources.value.findIndex(r => r.id === id);
    if (index !== -1) {
      resources.value.splice(index, 1);
    }
  }
}

function saveResource(resourceData: any) {
  if (editingResource.value) {
    const index = resources.value.findIndex(r => r.id === editingResource.value);
    if (index !== -1) {
      resources.value[index] = { ...resources.value[index], ...resourceData };
    }
  } else {
    resources.value.push({
      ...resourceData,
      id: resourceData.id || `resource-${resources.value.length + 1}`
    });
  }
  closeModal();
}

function closeModal() {
  showCreateModal.value = false;
  editingResource.value = null;
  editingResourceData.value = null;
}
</script>

<style scoped>
.resources-page {
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
  gap: 24px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  flex: 1;
  min-width: 200px;
  padding: 10px 16px;
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
}

.filter-dropdown {
  min-width: 150px;
}

.resources-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.resource-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-slow);
}

.resource-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.resource-header {
  margin-bottom: var(--spacing-md);
}

.resource-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.resource-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.resource-sensitivity {
  padding: var(--spacing-xs) var(--spacing-md);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.sensitivity-public {
  background: var(--color-sensitivity-public-bg);
  color: var(--color-sensitivity-public);
}

.sensitivity-internal {
  background: var(--color-sensitivity-internal-bg);
  color: var(--color-sensitivity-internal);
}

.sensitivity-confidential {
  background: var(--color-sensitivity-confidential-bg);
  color: var(--color-sensitivity-confidential);
}

.sensitivity-restricted {
  background: var(--color-sensitivity-restricted-bg);
  color: var(--color-sensitivity-restricted);
}

.resource-meta {
  display: flex;
  gap: var(--spacing-md);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.resource-type {
  text-transform: capitalize;
}

.resource-application {
  padding: 2px var(--spacing-sm);
  background: var(--color-info-bg);
  border-radius: var(--border-radius-xs);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.resource-attributes {
  margin-bottom: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
}

.attributes-preview {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.attribute-preview {
  display: flex;
  justify-content: space-between;
  font-size: var(--font-size-sm);
}

.attr-key {
  color: var(--color-text-muted);
}

.attr-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.more-attributes {
  font-size: var(--font-size-xs);
  color: var(--color-primary);
  font-style: italic;
}

.resource-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
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
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
}

.delete-btn {
  border-color: rgba(252, 129, 129, 0.3);
  color: var(--color-error);
}

.delete-btn:hover {
  background: var(--color-error-bg);
  border-color: rgba(252, 129, 129, 0.5);
  color: var(--color-error);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}
</style>

