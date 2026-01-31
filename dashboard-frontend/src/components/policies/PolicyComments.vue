<template>
  <div class="policy-comments">
    <div class="comments-header">
      <h3>Comments</h3>
      <button @click="showAddComment = true" class="btn-add-comment">
        <MessageSquare class="icon" />
        Add Comment
      </button>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading comments...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
    </div>

    <div v-else-if="comments.length === 0" class="empty-state">
      <p>No comments yet. Be the first to comment!</p>
    </div>

    <div v-else class="comments-list">
      <div
        v-for="comment in comments"
        :key="comment.id"
        class="comment-card"
        :class="{ 'is-reply': comment.parentId }"
      >
        <div class="comment-header">
          <div class="comment-author">
            <strong>{{ comment.userName }}</strong>
            <span class="comment-date">{{ formatDate(comment.createdAt) }}</span>
          </div>
          <div v-if="canEditComment(comment)" class="comment-actions">
            <button @click="editComment(comment)" class="btn-edit">
              <Edit class="icon" />
            </button>
            <button @click="deleteComment(comment)" class="btn-delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>

        <div class="comment-content">
          <p v-if="!editingComments[comment.id]">{{ comment.content }}</p>
          <div v-else class="edit-form">
            <textarea
              v-model="editingComments[comment.id]"
              class="edit-textarea"
              rows="3"
            ></textarea>
            <div class="edit-actions">
              <button @click="saveComment(comment)" class="btn-save">Save</button>
              <button @click="cancelEdit(comment.id)" class="btn-cancel">Cancel</button>
            </div>
          </div>
        </div>

        <div v-if="comment.mentions && comment.mentions.length > 0" class="comment-mentions">
          <span class="mention-label">Mentioned:</span>
          <span
            v-for="mention in comment.mentions"
            :key="mention"
            class="mention-tag"
          >
            @{{ mention }}
          </span>
        </div>
      </div>
    </div>

    <!-- Add Comment Modal -->
    <div v-if="showAddComment" class="modal-overlay" @click="showAddComment = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>Add Comment</h3>
          <button @click="showAddComment = false" class="btn-close">
            <X class="icon" />
          </button>
        </div>

        <form @submit.prevent="submitComment" class="modal-body">
          <div class="form-group">
            <label>Your Name</label>
            <input v-model="newComment.userName" type="text" required />
          </div>

          <div class="form-group">
            <label>Comment</label>
            <textarea
              v-model="newComment.content"
              rows="5"
              placeholder="Type your comment... Use @username to mention someone"
              required
            ></textarea>
            <small>Use @username to mention team members</small>
          </div>

          <div class="modal-footer">
            <button type="button" @click="showAddComment = false" class="btn-cancel">
              Cancel
            </button>
            <button type="submit" :disabled="submitting" class="btn-submit">
              {{ submitting ? 'Posting...' : 'Post Comment' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { MessageSquare, Edit, Trash2, X, AlertTriangle } from 'lucide-vue-next';
import axios from 'axios';

interface PolicyComment {
  id: string;
  policyId: string;
  userId: string;
  userName: string;
  content: string;
  createdAt: Date | string;
  updatedAt?: Date | string;
  parentId?: string;
  mentions?: string[];
}

const props = defineProps<{
  policyId: string;
  currentUserId?: string;
}>();

const comments = ref<PolicyComment[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const showAddComment = ref(false);
const submitting = ref(false);
const editingComments = ref<Record<string, string>>({});

const newComment = ref({
  userId: props.currentUserId || 'user-1',
  userName: '',
  content: '',
  parentId: undefined as string | undefined,
});

const loadComments = async () => {
  loading.value = true;
  error.value = null;

  try {
    const response = await axios.get(`/api/policies/${props.policyId}/comments`);
    comments.value = response.data.map((c: PolicyComment) => ({
      ...c,
      createdAt: new Date(c.createdAt),
      updatedAt: c.updatedAt ? new Date(c.updatedAt) : undefined,
    }));
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load comments';
    console.error('Error loading comments:', err);
  } finally {
    loading.value = false;
  }
};

const submitComment = async () => {
  if (!newComment.value.content.trim()) return;

  submitting.value = true;
  try {
    await axios.post(`/api/policies/${props.policyId}/comments`, {
      userId: newComment.value.userId,
      userName: newComment.value.userName,
      content: newComment.value.content,
      parentId: newComment.value.parentId,
    });

    await loadComments();
    showAddComment.value = false;
    newComment.value = {
      userId: props.currentUserId || 'user-1',
      userName: '',
      content: '',
      parentId: undefined,
    };
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to post comment';
    console.error('Error posting comment:', err);
  } finally {
    submitting.value = false;
  }
};

const editComment = (comment: PolicyComment) => {
  editingComments.value[comment.id] = comment.content;
};

const saveComment = async (comment: PolicyComment) => {
  const content = editingComments.value[comment.id];
  if (!content || !content.trim()) return;

  try {
    await axios.patch(`/api/policies/comments/${comment.id}`, {
      userId: comment.userId,
      content,
    });

    delete editingComments.value[comment.id];
    await loadComments();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to update comment';
    console.error('Error updating comment:', err);
  }
};

const cancelEdit = (commentId: string) => {
  delete editingComments.value[commentId];
};

const deleteComment = async (comment: PolicyComment) => {
  if (!confirm('Are you sure you want to delete this comment?')) {
    return;
  }

  try {
    await axios.delete(`/api/policies/comments/${comment.id}`, {
      params: { userId: comment.userId },
    });

    await loadComments();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to delete comment';
    console.error('Error deleting comment:', err);
  }
};

const canEditComment = (comment: PolicyComment): boolean => {
  return comment.userId === props.currentUserId || !props.currentUserId;
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

onMounted(() => {
  loadComments();
});
</script>

<style scoped>
.policy-comments {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.comments-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.comments-header h3 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
}

.btn-add-comment {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.icon {
  width: 18px;
  height: 18px;
}

.comments-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.comment-card {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.comment-card.is-reply {
  margin-left: var(--spacing-xl);
  border-left: 3px solid var(--color-primary);
}

.comment-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.comment-author {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.comment-author strong {
  color: var(--color-text-primary);
}

.comment-date {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.comment-actions {
  display: flex;
  gap: var(--spacing-xs);
}

.btn-edit,
.btn-delete {
  padding: var(--spacing-xs);
  background: transparent;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  opacity: 0.7;
  transition: var(--transition-all);
}

.btn-edit:hover {
  color: var(--color-info);
  opacity: 1;
}

.btn-delete:hover {
  color: var(--color-error);
  opacity: 1;
}

.comment-content {
  margin-bottom: var(--spacing-sm);
  color: var(--color-text-primary);
  line-height: 1.6;
}

.edit-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.edit-textarea {
  width: 100%;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-family: inherit;
}

.edit-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.btn-save,
.btn-cancel {
  padding: var(--spacing-xs) var(--spacing-sm);
  border: none;
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  cursor: pointer;
}

.btn-save {
  background: var(--color-primary);
  color: white;
}

.btn-cancel {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-primary);
}

.comment-mentions {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  flex-wrap: wrap;
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.mention-tag {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: rgba(var(--color-primary-rgb), 0.1);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--color-bg-primary);
  border-radius: var(--border-radius-lg);
  width: 90%;
  max-width: 600px;
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header h3 {
  margin: 0;
}

.btn-close {
  background: none;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  padding: var(--spacing-xs);
}

.modal-body {
  padding: var(--spacing-lg);
}

.form-group {
  margin-bottom: var(--spacing-md);
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-xs);
  font-weight: var(--font-weight-medium);
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-family: inherit;
}

.form-group small {
  display: block;
  margin-top: var(--spacing-xs);
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.btn-cancel,
.btn-submit {
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.btn-cancel {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-primary);
}

.btn-submit {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-submit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: var(--spacing-xl);
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  margin: 0 auto var(--spacing-md);
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}
</style>
