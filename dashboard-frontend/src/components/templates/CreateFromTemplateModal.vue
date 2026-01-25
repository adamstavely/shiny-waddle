<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isVisible" class="modal-overlay" @click="handleClose">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>Create Policy from Template: {{ templateName.toUpperCase() }}</h2>
            <button @click="handleClose" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
      <form @submit.prevent="handleSubmit" class="create-form">
        <div class="form-group">
          <label>Application Name *</label>
          <input
            v-model="form.applicationName"
            type="text"
            required
            placeholder="Enter application name"
          />
        </div>

        <!-- RBAC Config -->
        <template v-if="templateName === 'rbac'">
          <div class="form-group">
            <label>Roles (comma-separated)</label>
            <input
              v-model="rbacConfig.roles"
              type="text"
              placeholder="admin,user,viewer"
          />
          </div>
          <div class="form-group">
            <label>Resources (comma-separated)</label>
            <input
              v-model="rbacConfig.resources"
              type="text"
              placeholder="dataset,report"
          />
          </div>
          <div class="form-group">
            <label>Actions (comma-separated)</label>
            <input
              v-model="rbacConfig.actions"
              type="text"
              placeholder="read,write"
          />
          </div>
        </template>

        <!-- ABAC Config -->
        <template v-if="templateName === 'abac'">
          <div class="form-group">
            <label>Departments (comma-separated, optional)</label>
            <input
              v-model="abacConfig.departments"
              type="text"
              placeholder="engineering,research,finance"
          />
          </div>
          <div class="form-group">
            <label>Clearance Levels (comma-separated, optional)</label>
            <input
              v-model="abacConfig.clearanceLevels"
              type="text"
              placeholder="high,top-secret"
          />
          </div>
          <div class="form-group">
            <label>Data Classifications (comma-separated, optional)</label>
            <input
              v-model="abacConfig.dataClassifications"
              type="text"
              placeholder="confidential,restricted"
          />
          </div>
          <div class="form-group">
            <label>Projects (comma-separated, optional)</label>
            <input
              v-model="abacConfig.projects"
              type="text"
              placeholder="alpha,beta"
          />
          </div>
        </template>

        <!-- HIPAA Config -->
        <template v-if="templateName === 'hipaa'">
          <div class="form-group">
            <label>Covered Entities (comma-separated, optional)</label>
            <input
              v-model="hipaaConfig.coveredEntities"
              type="text"
              placeholder="hospital,clinic"
          />
          </div>
          <div class="form-group">
            <label>Business Associates (comma-separated, optional)</label>
            <input
              v-model="hipaaConfig.businessAssociates"
              type="text"
              placeholder="vendor1,vendor2"
          />
          </div>
        </template>

        <!-- GDPR Config -->
        <template v-if="templateName === 'gdpr'">
          <div class="form-group">
            <label>Data Controllers (comma-separated, optional)</label>
            <input
              v-model="gdprConfig.dataControllers"
              type="text"
              placeholder="company1,company2"
          />
          </div>
          <div class="form-group">
            <label>Data Processors (comma-separated, optional)</label>
            <input
              v-model="gdprConfig.dataProcessors"
              type="text"
              placeholder="vendor1,vendor2"
          />
          </div>
          <div class="form-group">
            <label>EU Member States (comma-separated, optional)</label>
            <input
              v-model="gdprConfig.euMemberStates"
              type="text"
              placeholder="DE,FR,IT"
          />
          </div>
        </template>

        <div class="form-actions">
          <button type="button" @click="handleClose" class="btn btn-secondary">
            Cancel
          </button>
          <button type="submit" :disabled="creating" class="btn btn-primary">
            <span v-if="creating">Creating...</span>
            <span v-else>Create Policy</span>
          </button>
        </div>
      </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Teleport, Transition } from 'vue';
import { X } from 'lucide-vue-next';
import { useTemplates } from '../../composables/useTemplates';

const props = defineProps<{
  templateName: string;
}>();

const emit = defineEmits<{
  close: [];
  created: [];
}>();

const { createFromTemplate, loading: creating } = useTemplates();

const isVisible = ref(true);

watch(() => props.templateName, () => {
  // Reset visibility when template name changes
  isVisible.value = true;
});

const handleClose = () => {
  isVisible.value = false;
  emit('close');
};

const form = ref({
  applicationName: '',
});

const rbacConfig = ref({
  roles: 'admin,user,viewer',
  resources: 'dataset,report',
  actions: 'read,write',
});

const abacConfig = ref({
  departments: '',
  clearanceLevels: '',
  dataClassifications: '',
  projects: '',
});

const hipaaConfig = ref({
  coveredEntities: '',
  businessAssociates: '',
});

const gdprConfig = ref({
  dataControllers: '',
  dataProcessors: '',
  euMemberStates: '',
});

const getConfig = () => {
  const baseConfig: any = {};
  
  if (props.templateName === 'rbac') {
    baseConfig.roles = rbacConfig.value.roles.split(',').map(s => s.trim()).filter(Boolean);
    baseConfig.resources = rbacConfig.value.resources.split(',').map(s => s.trim()).filter(Boolean);
    baseConfig.actions = rbacConfig.value.actions.split(',').map(s => s.trim()).filter(Boolean);
  } else if (props.templateName === 'abac') {
    if (abacConfig.value.departments) {
      baseConfig.departments = abacConfig.value.departments.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (abacConfig.value.clearanceLevels) {
      baseConfig.clearanceLevels = abacConfig.value.clearanceLevels.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (abacConfig.value.dataClassifications) {
      baseConfig.dataClassifications = abacConfig.value.dataClassifications.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (abacConfig.value.projects) {
      baseConfig.projects = abacConfig.value.projects.split(',').map(s => s.trim()).filter(Boolean);
    }
  } else if (props.templateName === 'hipaa') {
    if (hipaaConfig.value.coveredEntities) {
      baseConfig.coveredEntities = hipaaConfig.value.coveredEntities.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (hipaaConfig.value.businessAssociates) {
      baseConfig.businessAssociates = hipaaConfig.value.businessAssociates.split(',').map(s => s.trim()).filter(Boolean);
    }
  } else if (props.templateName === 'gdpr') {
    if (gdprConfig.value.dataControllers) {
      baseConfig.dataControllers = gdprConfig.value.dataControllers.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (gdprConfig.value.dataProcessors) {
      baseConfig.dataProcessors = gdprConfig.value.dataProcessors.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (gdprConfig.value.euMemberStates) {
      baseConfig.euMemberStates = gdprConfig.value.euMemberStates.split(',').map(s => s.trim()).filter(Boolean);
    }
  }

  return baseConfig;
};

const handleSubmit = async () => {
  try {
    await createFromTemplate(props.templateName, {
      applicationName: form.value.applicationName,
      config: getConfig(),
    });
    handleClose();
    emit('created');
  } catch (error) {
    // Error is handled by composable
  }
};
</script>

<style scoped>
.create-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  font-size: 0.9rem;
}

.form-group input {
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  margin-top: 1rem;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  max-width: 90vw;
  max-height: 90vh;
  overflow: auto;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  display: flex;
  flex-direction: column;
  min-width: 600px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.modal-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #a0aec0;
  transition: color 0.2s;
}

.modal-close:hover {
  color: #ffffff;
}

.modal-body {
  padding: 1.5rem;
  flex: 1;
  overflow-y: auto;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.form-group label {
  color: #ffffff;
}

.form-group input {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  color: #ffffff;
}

.form-group input:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.5);
}

.btn {
  padding: 0.75rem 1.5rem;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}
</style>
