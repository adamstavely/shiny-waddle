<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Shield class="modal-title-icon" />
              <h2>{{ role ? 'Edit Role' : 'Add Role' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="save" class="role-form">
              <div class="form-group">
                <label>Role Name *</label>
                <input v-model="form.name" type="text" required />
              </div>
              <div class="form-group">
                <label>Description</label>
                <textarea v-model="form.description" rows="3"></textarea>
              </div>
              <div class="form-group">
                <label>Permissions</label>
                <div class="permissions-input">
                  <span
                    v-for="(perm, index) in form.permissions"
                    :key="index"
                    class="permission-tag"
                  >
                    {{ perm }}
                    <button type="button" @click="removePermission(index)" class="tag-remove">
                      <X class="tag-icon" />
                    </button>
                  </span>
                  <input
                    v-model="newPermission"
                    type="text"
                    placeholder="Add permission and press Enter"
                    @keydown.enter.prevent="addPermission"
                    class="tag-input"
                  />
                </div>
                <small>Press Enter to add a permission</small>
              </div>
              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary">Save Role</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { Teleport } from 'vue';
import { Shield, X } from 'lucide-vue-next';

interface Props {
  show: boolean;
  role?: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [data: any];
}>();

const form = ref({
  name: '',
  description: '',
  permissions: [] as string[]
});

const newPermission = ref('');

watch(() => props.role, (role) => {
  if (role) {
    form.value = {
      name: role.name || '',
      description: role.description || '',
      permissions: [...(role.permissions || [])]
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
    name: '',
    description: '',
    permissions: []
  };
  newPermission.value = '';
}

function addPermission() {
  if (newPermission.value.trim() && !form.value.permissions.includes(newPermission.value.trim())) {
    form.value.permissions.push(newPermission.value.trim());
    newPermission.value = '';
  }
}

function removePermission(index: number) {
  form.value.permissions.splice(index, 1);
}

function close() {
  emit('close');
}

function save() {
  emit('save', { ...form.value });
}
</script>

<style scoped>
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

.role-form {
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
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.permissions-input {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  min-height: 48px;
}

.permission-tag {
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

