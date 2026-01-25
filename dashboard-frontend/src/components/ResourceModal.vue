<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Database class="modal-title-icon" />
              <h2>{{ resource ? 'Edit Resource' : 'Add Resource' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="save" class="resource-form">
              <div class="form-group">
                <label>Resource ID *</label>
                <input v-model="form.id" type="text" required />
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Type *</label>
                  <input v-model="form.type" type="text" required />
                </div>
                <div class="form-group">
                  <label>Sensitivity</label>
                  <select v-model="form.sensitivity">
                    <option value="">None</option>
                    <option value="public">Public</option>
                    <option value="internal">Internal</option>
                    <option value="confidential">Confidential</option>
                    <option value="restricted">Restricted</option>
                  </select>
                </div>
              </div>
              <div class="form-group">
                <label>Application</label>
                <input v-model="form.application" type="text" />
              </div>

              <div class="section-divider">
                <h3>ABAC Attributes</h3>
              </div>

              <div class="form-group">
                <label>Data Classification</label>
                <select v-model="form.abacAttributes.dataClassification">
                  <option value="">None</option>
                  <option value="public">Public</option>
                  <option value="internal">Internal</option>
                  <option value="confidential">Confidential</option>
                  <option value="restricted">Restricted</option>
                  <option value="top-secret">Top Secret</option>
                </select>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label>Department</label>
                  <input v-model="form.abacAttributes.department" type="text" />
                </div>
                <div class="form-group">
                  <label>Project</label>
                  <input v-model="form.abacAttributes.project" type="text" />
                </div>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label>Region</label>
                  <input v-model="form.abacAttributes.region" type="text" />
                </div>
                <div class="form-group">
                  <label>Owner</label>
                  <input v-model="form.abacAttributes.owner" type="text" />
                </div>
              </div>

              <div class="form-group">
                <label>Minimum Clearance Level</label>
                <select v-model="form.abacAttributes.minClearanceLevel">
                  <option value="">None</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="top-secret">Top Secret</option>
                </select>
              </div>

              <div class="form-group">
                <label>Required Certifications</label>
                <div class="tags-input">
                  <span
                    v-for="(cert, index) in certificationsList"
                    :key="index"
                    class="tag"
                  >
                    {{ cert }}
                    <button type="button" @click="removeCertification(index)" class="tag-remove">
                      <X class="tag-icon" />
                    </button>
                  </span>
                  <input
                    v-model="newCertification"
                    type="text"
                    placeholder="Add certification and press Enter"
                    @keydown.enter.prevent="addCertification"
                    class="tag-input"
                  />
                </div>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary">Save Resource</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { Teleport } from 'vue';
import { Database, X } from 'lucide-vue-next';

interface Props {
  show: boolean;
  resource?: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [data: any];
}>();

const form = ref({
  id: '',
  type: '',
  sensitivity: '',
  application: '',
  abacAttributes: {
    dataClassification: '',
    department: '',
    project: '',
    region: '',
    owner: '',
    minClearanceLevel: '',
    requiresCertification: [] as string[]
  }
});

const newCertification = ref('');

const certificationsList = computed({
  get: () => form.value.abacAttributes.requiresCertification || [],
  set: (val) => {
    form.value.abacAttributes.requiresCertification = val;
  }
});

watch(() => props.resource, (resource) => {
  if (resource) {
    form.value = {
      id: resource.id || '',
      type: resource.type || '',
      sensitivity: resource.sensitivity || '',
      application: resource.application || '',
      abacAttributes: {
        dataClassification: resource.abacAttributes?.dataClassification || '',
        department: resource.abacAttributes?.department || '',
        project: resource.abacAttributes?.project || '',
        region: resource.abacAttributes?.region || '',
        owner: resource.abacAttributes?.owner || '',
        minClearanceLevel: resource.abacAttributes?.minClearanceLevel || '',
        requiresCertification: resource.abacAttributes?.requiresCertification || []
      }
    };
  } else {
    resetForm();
  }
}, { immediate: true });

watch(() => props.show, (show) => {
  if (!show) {
    resetForm();
  }
});

function resetForm() {
  form.value = {
    id: '',
    type: '',
    sensitivity: '',
    application: '',
    abacAttributes: {
      dataClassification: '',
      department: '',
      project: '',
      region: '',
      owner: '',
      minClearanceLevel: '',
      requiresCertification: []
    }
  };
  newCertification.value = '';
}

function addCertification() {
  if (newCertification.value.trim() && !certificationsList.value.includes(newCertification.value.trim())) {
    certificationsList.value.push(newCertification.value.trim());
    newCertification.value = '';
  }
}

function removeCertification(index: number) {
  certificationsList.value.splice(index, 1);
}

function close() {
  emit('close');
}

function save() {
  emit('save', { ...form.value });
}
</script>

<style scoped>
.large-modal {
  max-width: 700px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.resource-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.section-divider {
  margin: 24px 0 16px 0;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.section-divider h3 {
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.tags-input {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  min-height: 48px;
}

.tag {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
}

.tag-remove {
  display: flex;
  align-items: center;
  padding: 2px;
  background: transparent;
  border: none;
  cursor: pointer;
  color: #4facfe;
  transition: color 0.2s;
}

.tag-remove:hover {
  color: #fc8181;
}

.tag-icon {
  width: 12px;
  height: 12px;
}

.tag-input {
  flex: 1;
  min-width: 150px;
  background: transparent;
  border: none;
  color: #ffffff;
  font-size: 0.9rem;
  outline: none;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-primary {
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

