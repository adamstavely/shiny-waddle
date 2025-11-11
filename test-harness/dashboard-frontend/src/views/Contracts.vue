<template>
  <div class="contracts-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Contracts</h1>
          <p class="page-description">Manage data owner contracts and requirements</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Contract
        </button>
      </div>
    </div>

    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search contracts..."
        class="search-input"
      />
      <Dropdown
        v-model="filterDataOwner"
        :options="dataOwnerOptions"
        placeholder="All Data Owners"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
    </div>

    <div class="contracts-grid">
      <div
        v-for="contract in filteredContracts"
        :key="contract.id"
        class="contract-card"
        @click="viewContractDetails(contract.id)"
      >
        <div class="contract-header">
          <div class="contract-title-row">
            <h3 class="contract-name">{{ contract.name }}</h3>
            <span class="contract-status" :class="`status-${contract.status}`">
              {{ contract.status }}
            </span>
          </div>
          <div class="contract-meta">
            <span class="contract-owner">Owner: {{ contract.dataOwner }}</span>
            <span class="contract-version" v-if="contract.version">v{{ contract.version }}</span>
          </div>
        </div>

        <div class="contract-details">
          <div class="detail-item">
            <span class="detail-label">Requirements:</span>
            <span class="detail-value">{{ contract.requirements?.length || 0 }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Machine Readable:</span>
            <span class="detail-value" :class="contract.machineReadable ? 'value-success' : 'value-warning'">
              {{ contract.machineReadable ? 'Yes' : 'No' }}
            </span>
          </div>
          <div class="detail-item" v-if="contract.lastTested">
            <span class="detail-label">Last Tested:</span>
            <span class="detail-value">{{ formatRelativeTime(contract.lastTested) }}</span>
          </div>
        </div>

        <div class="contract-requirements-preview" v-if="contract.requirements && contract.requirements.length > 0">
          <div
            v-for="req in contract.requirements.slice(0, 2)"
            :key="req.id"
            class="requirement-preview"
          >
            <span class="req-type">{{ req.type }}</span>
            <span class="req-description">{{ req.description }}</span>
          </div>
          <span v-if="contract.requirements.length > 2" class="more-requirements">
            +{{ contract.requirements.length - 2 }} more requirements
          </span>
        </div>

        <div class="contract-actions">
          <button @click.stop="testContract(contract.id)" class="action-btn test-btn">
            <Play class="action-icon" />
            Test
          </button>
          <button @click.stop="editContract(contract.id)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click.stop="viewVersions(contract.id)" class="action-btn versions-btn">
            <History class="action-icon" />
            Versions
          </button>
          <button @click.stop="deleteContract(contract.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredContracts.length === 0" class="empty-state">
      <FileText class="empty-icon" />
      <h3>No contracts found</h3>
      <p>Create your first contract to get started</p>
      <button @click="showCreateModal = true" class="btn-primary">
        Add Contract
      </button>
    </div>

    <!-- Contract Modal -->
    <ContractModal
      :show="showCreateModal || editingContract"
      :contract="editingContractData"
      @close="closeModal"
      @save="saveContract"
    />

    <!-- Contract Detail Modal -->
    <ContractDetailModal
      :show="showDetailModal"
      :contract="selectedContract"
      @close="closeDetailModal"
      @test="testContract"
    />

    <!-- Contract Versions Modal -->
    <ContractVersionsModal
      :show="showVersionsModal"
      :contract="selectedContract"
      @close="closeVersionsModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  FileText,
  Plus,
  Edit,
  Trash2,
  Play,
  History
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ContractModal from '../components/ContractModal.vue';
import ContractDetailModal from '../components/ContractDetailModal.vue';
import ContractVersionsModal from '../components/ContractVersionsModal.vue';

const breadcrumbItems = [
  { label: 'Contracts', icon: FileText }
];

const searchQuery = ref('');
const filterDataOwner = ref('');
const filterStatus = ref('');
const showCreateModal = ref(false);
const showDetailModal = ref(false);
const showVersionsModal = ref(false);
const editingContract = ref<string | null>(null);
const editingContractData = ref<any>(null);
const selectedContract = ref<any>(null);

// Contracts data
const contracts = ref([
  {
    id: '1',
    name: 'No Raw Email Export',
    dataOwner: 'data-governance',
    status: 'active',
    version: 1,
    machineReadable: true,
    lastTested: new Date(Date.now() - 2 * 60 * 60 * 1000),
    requirements: [
      {
        id: 'no-email-export',
        description: 'No raw email addresses may be exported',
        type: 'export-restriction',
        rule: {
          restrictedFields: ['email'],
          requireMasking: true
        },
        enforcement: 'hard'
      }
    ]
  },
  {
    id: '2',
    name: 'Minimum Aggregation k=10',
    dataOwner: 'data-governance',
    status: 'active',
    version: 2,
    machineReadable: true,
    lastTested: new Date(Date.now() - 5 * 60 * 60 * 1000),
    requirements: [
      {
        id: 'min-aggregation',
        description: 'Queries must aggregate to minimum k=10 records',
        type: 'aggregation-requirement',
        rule: {
          minK: 10,
          requireAggregation: true
        },
        enforcement: 'hard'
      },
      {
        id: 'field-restriction',
        description: 'SSN field cannot be accessed directly',
        type: 'field-restriction',
        rule: {
          fields: ['ssn'],
          allowed: false
        },
        enforcement: 'hard'
      }
    ]
  },
  {
    id: '3',
    name: 'GDPR Compliance',
    dataOwner: 'legal',
    status: 'draft',
    version: 1,
    machineReadable: false,
    lastTested: null,
    requirements: [
      {
        id: 'no-pii-export',
        description: 'No PII fields may be exported',
        type: 'export-restriction',
        rule: {
          restrictedFields: ['email', 'ssn', 'phone'],
          requireMasking: true
        },
        enforcement: 'hard'
      }
    ]
  }
]);

const dataOwnerOptions = computed(() => {
  const owners = [...new Set(contracts.value.map(c => c.dataOwner))];
  return [
    { label: 'All Data Owners', value: '' },
    ...owners.map(owner => ({ label: owner, value: owner }))
  ];
});

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Active', value: 'active' },
  { label: 'Draft', value: 'draft' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const filteredContracts = computed(() => {
  return contracts.value.filter(contract => {
    const matchesSearch = contract.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         contract.dataOwner.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesOwner = !filterDataOwner.value || contract.dataOwner === filterDataOwner.value;
    const matchesStatus = !filterStatus.value || contract.status === filterStatus.value;
    return matchesSearch && matchesOwner && matchesStatus;
  });
});

function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
}

function viewContractDetails(id: string) {
  const contract = contracts.value.find(c => c.id === id);
  if (contract) {
    selectedContract.value = contract;
    showDetailModal.value = true;
  }
}

function closeDetailModal() {
  showDetailModal.value = false;
  selectedContract.value = null;
}

function editContract(id: string) {
  const contract = contracts.value.find(c => c.id === id);
  if (contract) {
    editingContract.value = id;
    editingContractData.value = contract;
    showCreateModal.value = true;
  }
}

function deleteContract(id: string) {
  if (confirm('Are you sure you want to delete this contract?')) {
    const index = contracts.value.findIndex(c => c.id === id);
    if (index !== -1) {
      contracts.value.splice(index, 1);
    }
  }
}

function testContract(id: string) {
  const contract = contracts.value.find(c => c.id === id);
  if (contract) {
    // Simulate testing
    contract.lastTested = new Date();
    console.log('Testing contract:', contract.name);
  }
}

function viewVersions(id: string) {
  const contract = contracts.value.find(c => c.id === id);
  if (contract) {
    selectedContract.value = contract;
    showVersionsModal.value = true;
  }
}

function closeVersionsModal() {
  showVersionsModal.value = false;
  selectedContract.value = null;
}

function saveContract(contractData: any) {
  if (editingContract.value) {
    const index = contracts.value.findIndex(c => c.id === editingContract.value);
    if (index !== -1) {
      // Create new version
      const oldContract = contracts.value[index];
      contracts.value[index] = {
        ...oldContract,
        ...contractData,
        version: (oldContract.version || 1) + 1
      };
    }
  } else {
    contracts.value.push({
      id: String(contracts.value.length + 1),
      ...contractData,
      status: 'draft',
      version: 1,
      lastTested: null
    });
  }
  closeModal();
}

function closeModal() {
  showCreateModal.value = false;
  editingContract.value = null;
  editingContractData.value = null;
}
</script>

<style scoped>
.contracts-page {
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

.contracts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

.contract-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.contract-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.contract-header {
  margin-bottom: 16px;
}

.contract-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.contract-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.contract-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-draft {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-deprecated {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.contract-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.contract-owner {
  font-weight: 500;
}

.contract-version {
  padding: 2px 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.contract-details {
  margin-bottom: 16px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-item:last-child {
  border-bottom: none;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
}

.detail-value {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.value-success {
  color: #22c55e;
}

.value-warning {
  color: #fbbf24;
}

.contract-requirements-preview {
  margin-bottom: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.requirement-preview {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.requirement-preview:last-child {
  border-bottom: none;
}

.req-type {
  padding: 2px 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
  width: fit-content;
}

.req-description {
  font-size: 0.875rem;
  color: #a0aec0;
}

.more-requirements {
  font-size: 0.75rem;
  color: #4facfe;
  font-style: italic;
  margin-top: 8px;
  display: block;
}

.contract-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.test-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.delete-btn {
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 24px;
}
</style>

