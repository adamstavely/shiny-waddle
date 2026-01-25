<template>
  <div class="validators-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Validators</h1>
          <p class="page-description">Manage registered validators that execute compliance tests</p>
        </div>
        <button @click="showAddValidatorModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Validator
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading">Loading validators...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <button @click="loadValidators" class="btn-secondary">Retry</button>
    </div>
    <div v-else-if="validators.length === 0" class="empty-state">
      <EmptyState
        title="No validators registered"
        description="Add your first validator to start running compliance tests"
        :icon="Shield"
        action-label="Add Validator"
        :show-default-action="true"
        @action="showAddValidatorModal = true"
      />
    </div>
    <div v-else class="validators-grid">
      <ValidatorCard
        v-for="validator in validators"
        :key="validator.id"
        :validator="validator"
        @view="viewValidator"
        @toggle="toggleValidator"
        @test="testValidator"
        @delete="deleteValidator"
      />
    </div>

    <!-- Validator Modals -->
    <ValidatorDetailModal
      :show="showValidatorDetailModal"
      :validator="selectedValidator"
      @close="showValidatorDetailModal = false; selectedValidator = null"
      @edit="editValidator"
      @toggle="toggleValidator"
      @test="testValidator"
    />

    <AddValidatorModal
      :show="showAddValidatorModal"
      :validator="editingValidator"
      @close="showAddValidatorModal = false; editingValidator = null"
      @submit="handleValidatorSubmit"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Shield, Plus } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import EmptyState from '../components/EmptyState.vue';
import ValidatorCard from '../components/ValidatorCard.vue';
import ValidatorDetailModal from '../components/ValidatorDetailModal.vue';
import AddValidatorModal from '../components/AddValidatorModal.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Validators' }
];

const validators = ref<any[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const showAddValidatorModal = ref(false);
const showValidatorDetailModal = ref(false);
const selectedValidator = ref<any>(null);
const editingValidator = ref<any>(null);

const loadValidators = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/validators');
    validators.value = response.data.map((v: any) => ({
      ...v,
      registeredAt: new Date(v.registeredAt),
      lastRunAt: v.lastRunAt ? new Date(v.lastRunAt) : null,
      updatedAt: new Date(v.updatedAt),
    }));
  } catch (err: any) {
    error.value = err.message || 'Failed to load validators';
    console.error('Error loading validators:', err);
  } finally {
    loading.value = false;
  }
};

const viewValidator = (validator: any) => {
  selectedValidator.value = validator;
  showValidatorDetailModal.value = true;
};

const toggleValidator = async (validator: any) => {
  try {
    if (validator.enabled) {
      await axios.patch(`/api/validators/${validator.id}/disable`);
    } else {
      await axios.patch(`/api/validators/${validator.id}/enable`);
    }
    await loadValidators();
  } catch (err: any) {
    console.error('Error toggling validator:', err);
    alert(err.response?.data?.message || 'Failed to toggle validator');
  }
};

const testValidator = async (validator: any) => {
  try {
    const response = await axios.post(`/api/validators/${validator.id}/test`);
    alert(response.data.message || 'Connection test successful');
  } catch (err: any) {
    console.error('Error testing validator:', err);
    alert(err.response?.data?.message || 'Connection test failed');
  }
};

const deleteValidator = async (validator: any) => {
  if (!confirm(`Are you sure you want to delete validator "${validator.name}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/validators/${validator.id}`);
    await loadValidators();
  } catch (err: any) {
    console.error('Error deleting validator:', err);
    alert(err.response?.data?.message || 'Failed to delete validator');
  }
};

const editValidator = (validator: any) => {
  editingValidator.value = validator;
  showAddValidatorModal.value = true;
};

const handleValidatorSubmit = async (data: any) => {
  try {
    if (editingValidator.value) {
      await axios.patch(`/api/validators/${editingValidator.value.id}`, data);
    } else {
      await axios.post('/api/validators', data);
    }
    await loadValidators();
    showAddValidatorModal.value = false;
    editingValidator.value = null;
  } catch (err: any) {
    console.error('Error saving validator:', err);
    alert(err.response?.data?.message || 'Failed to save validator');
  }
};

onMounted(() => {
  loadValidators();
});
</script>

<style scoped>
.validators-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.loading-state,
.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-2xl);
  gap: var(--spacing-md);
}

.loading {
  color: var(--color-text-secondary);
}

.error {
  color: var(--color-error);
}

.validators-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.empty-state {
  padding: var(--spacing-2xl);
}
</style>
