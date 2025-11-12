<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <AlertTriangle class="modal-title-icon" :class="`icon-${violation?.severity}`" />
              <h2>{{ violation?.title }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body" v-if="violation">
            <!-- Status and Severity Badges -->
            <div class="badges-section">
              <span class="severity-badge" :class="`badge-${violation.severity}`">
                {{ violation.severity }}
              </span>
              <span class="status-badge" :class="`status-${violation.status}`">
                {{ violation.status }}
              </span>
            </div>

            <!-- Basic Information -->
            <div class="detail-section">
              <h3 class="section-title">Violation Details</h3>
              <div class="info-grid">
                <div class="info-item">
                  <span class="info-label">Type</span>
                  <span class="info-value">{{ formatType(violation.type) }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Detected At</span>
                  <span class="info-value">{{ formatDate(violation.detectedAt) }}</span>
                </div>
                <div class="info-item" v-if="violation.application">
                  <span class="info-label">Application</span>
                  <span class="info-value">{{ violation.application }}</span>
                </div>
                <div class="info-item" v-if="violation.team">
                  <span class="info-label">Team</span>
                  <span class="info-value">{{ violation.team }}</span>
                </div>
                <div class="info-item" v-if="violation.policyName">
                  <span class="info-label">Policy</span>
                  <span class="info-value">{{ violation.policyName }}</span>
                </div>
                <div class="info-item" v-if="violation.resource">
                  <span class="info-label">Resource</span>
                  <span class="info-value">{{ violation.resource }}</span>
                </div>
                <div class="info-item" v-if="violation.assignedTo">
                  <span class="info-label">Assigned To</span>
                  <span class="info-value">{{ violation.assignedTo }}</span>
                </div>
              </div>
            </div>

            <!-- Description -->
            <div class="detail-section">
              <h3 class="section-title">Description</h3>
              <p class="description-text">{{ violation.description }}</p>
            </div>

            <!-- Affected Resources -->
            <div class="detail-section" v-if="violation.affectedResources && violation.affectedResources.length > 0">
              <h3 class="section-title">Affected Resources</h3>
              <div class="resources-list">
                <span v-for="resource in violation.affectedResources" :key="resource" class="resource-badge">
                  {{ resource }}
                </span>
              </div>
            </div>

            <!-- Test Results -->
            <div class="detail-section" v-if="violation.testResultId || violation.testResultDetails">
              <h3 class="section-title">Test Results</h3>
              <div v-if="violation.testResultId" class="info-item">
                <span class="info-label">Test Result ID</span>
                <span class="info-value">{{ violation.testResultId }}</span>
              </div>
              <div v-if="violation.testResultDetails" class="test-details">
                <pre>{{ JSON.stringify(violation.testResultDetails, null, 2) }}</pre>
              </div>
            </div>

            <!-- Remediation Suggestions -->
            <div class="detail-section" v-if="violation.remediationSuggestions && violation.remediationSuggestions.length > 0">
              <h3 class="section-title">Remediation Suggestions</h3>
              <ul class="suggestions-list">
                <li v-for="(suggestion, index) in violation.remediationSuggestions" :key="index">
                  {{ suggestion }}
                </li>
              </ul>
            </div>

            <!-- Remediation Status -->
            <div class="detail-section" v-if="violation.remediationStatus">
              <h3 class="section-title">Remediation Status</h3>
              <p class="remediation-status">{{ violation.remediationStatus }}</p>
            </div>

            <!-- Remediation Timeline -->
            <div class="detail-section" v-if="violation.remediationTimeline && violation.remediationTimeline.length > 0">
              <h3 class="section-title">Remediation Timeline</h3>
              <div class="timeline">
                <div v-for="event in violation.remediationTimeline" :key="event.id" class="timeline-item">
                  <div class="timeline-marker"></div>
                  <div class="timeline-content">
                    <div class="timeline-header">
                      <span class="timeline-type">{{ formatEventType(event.type) }}</span>
                      <span class="timeline-time">{{ formatDate(event.timestamp) }}</span>
                    </div>
                    <p class="timeline-description">{{ event.description }}</p>
                    <span class="timeline-actor">by {{ event.actor }}</span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Comments -->
            <div class="detail-section">
              <h3 class="section-title">Comments</h3>
              <div class="comments-list" v-if="violation.comments && violation.comments.length > 0">
                <div v-for="comment in violation.comments" :key="comment.id" class="comment-item">
                  <div class="comment-header">
                    <span class="comment-author">{{ comment.author }}</span>
                    <span class="comment-date">{{ formatDate(comment.createdAt) }}</span>
                  </div>
                  <p class="comment-content">{{ comment.content }}</p>
                </div>
              </div>
              <div v-else class="no-comments">
                <p>No comments yet</p>
              </div>
              <div class="add-comment">
                <textarea
                  v-model="newComment"
                  placeholder="Add a comment..."
                  class="comment-input"
                  rows="3"
                ></textarea>
                <button @click="addComment" class="comment-submit-btn" :disabled="!newComment.trim()">
                  Add Comment
                </button>
              </div>
            </div>

            <!-- Related Violations -->
            <div class="detail-section" v-if="violation.relatedViolationIds && violation.relatedViolationIds.length > 0">
              <h3 class="section-title">Related Violations</h3>
              <div class="related-violations">
                <button
                  v-for="relatedId in violation.relatedViolationIds"
                  :key="relatedId"
                  @click="viewRelatedViolation(relatedId)"
                  class="related-violation-link"
                >
                  View Violation {{ relatedId }}
                </button>
              </div>
            </div>

            <!-- Tickets -->
            <div class="detail-section" v-if="tickets.length > 0">
              <h3 class="section-title">Related Tickets</h3>
              <div class="tickets-list">
                <a
                  v-for="ticket in tickets"
                  :key="ticket.id"
                  :href="ticket.externalUrl"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="ticket-link"
                >
                  <Ticket class="ticket-icon" />
                  <div class="ticket-info">
                    <span class="ticket-id">{{ ticket.externalId }}</span>
                    <span class="ticket-status" :class="`status-${ticket.status}`">{{ formatTicketStatus(ticket.status) }}</span>
                  </div>
                  <ExternalLink class="external-icon" />
                </a>
              </div>
            </div>

            <!-- Actions -->
            <div class="modal-actions">
              <button @click="createTicket" class="action-btn ticket-btn" :disabled="creatingTicket || !hasEnabledIntegration">
                <Ticket class="action-icon" />
                {{ creatingTicket ? 'Creating...' : 'Create Ticket' }}
              </button>
              <button @click="assignViolation" class="action-btn assign-btn">
                <User class="action-icon" />
                {{ violation.assignedTo ? 'Reassign' : 'Assign' }}
              </button>
              <button @click="resolveViolation" class="action-btn resolve-btn" v-if="violation.status !== 'resolved'">
                <CheckCircle2 class="action-icon" />
                Mark as Resolved
              </button>
              <button @click="ignoreViolation" class="action-btn ignore-btn" v-if="violation.status !== 'ignored'">
                <X class="action-icon" />
                Ignore
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import { AlertTriangle, X, User, CheckCircle2, Ticket, ExternalLink } from 'lucide-vue-next';
import type { ViolationEntity } from '../types/violation';
import type { Ticket as TicketType, TicketingIntegration } from '../types/ticketing';

interface Props {
  show: boolean;
  violation: ViolationEntity | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  update: [violation: ViolationEntity];
  viewRelated: [id: string];
}>();

const newComment = ref('');
const currentUser = ref('current-user@example.com'); // TODO: Get from auth context
const tickets = ref<TicketType[]>([]);
const integrations = ref<TicketingIntegration[]>([]);
const creatingTicket = ref(false);
const hasEnabledIntegration = ref(false);

const formatType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const formatDate = (date: Date | string | undefined): string => {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return 'Invalid date';
  return d.toLocaleString();
};

const formatEventType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const addComment = async () => {
  if (!props.violation || !newComment.value.trim()) return;

  try {
    const response = await fetch(`http://localhost:3001/api/violations/${props.violation.id}/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        author: currentUser.value,
        content: newComment.value.trim(),
      }),
    });

    if (response.ok) {
      const comment = await response.json();
      // Reload violation to get updated comments
      const violationResponse = await fetch(`http://localhost:3001/api/violations/${props.violation!.id}`);
      if (violationResponse.ok) {
        const updatedViolation = await violationResponse.json();
        // Convert date strings to Date objects
        const violation = {
          ...updatedViolation,
          detectedAt: new Date(updatedViolation.detectedAt),
          resolvedAt: updatedViolation.resolvedAt ? new Date(updatedViolation.resolvedAt) : undefined,
          ignoredAt: updatedViolation.ignoredAt ? new Date(updatedViolation.ignoredAt) : undefined,
          createdAt: new Date(updatedViolation.createdAt),
          updatedAt: new Date(updatedViolation.updatedAt),
        };
        emit('update', violation);
        newComment.value = '';
      }
    }
  } catch (error) {
    console.error('Error adding comment:', error);
  }
};

const assignViolation = async () => {
  if (!props.violation) return;
  
  const assignee = prompt('Enter assignee email:', props.violation.assignedTo || '');
  if (assignee === null) return;

  try {
    const response = await fetch(`http://localhost:3001/api/violations/${props.violation.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        assignedTo: assignee || null,
        status: assignee ? 'in-progress' : props.violation.status,
      }),
    });

    if (response.ok) {
      const updatedViolation = await response.json();
      // Convert date strings to Date objects
      const violation = {
        ...updatedViolation,
        detectedAt: new Date(updatedViolation.detectedAt),
        resolvedAt: updatedViolation.resolvedAt ? new Date(updatedViolation.resolvedAt) : undefined,
        ignoredAt: updatedViolation.ignoredAt ? new Date(updatedViolation.ignoredAt) : undefined,
        createdAt: new Date(updatedViolation.createdAt),
        updatedAt: new Date(updatedViolation.updatedAt),
      };
      emit('update', violation);
    }
  } catch (error) {
    console.error('Error assigning violation:', error);
  }
};

const resolveViolation = async () => {
  if (!props.violation || !confirm('Mark this violation as resolved?')) return;

  try {
    const response = await fetch(`http://localhost:3001/api/violations/${props.violation.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'resolved',
        resolvedAt: new Date().toISOString(),
        resolvedBy: currentUser.value,
      }),
    });

    if (response.ok) {
      const updatedViolation = await response.json();
      // Convert date strings to Date objects
      const violation = {
        ...updatedViolation,
        detectedAt: new Date(updatedViolation.detectedAt),
        resolvedAt: updatedViolation.resolvedAt ? new Date(updatedViolation.resolvedAt) : undefined,
        ignoredAt: updatedViolation.ignoredAt ? new Date(updatedViolation.ignoredAt) : undefined,
        createdAt: new Date(updatedViolation.createdAt),
        updatedAt: new Date(updatedViolation.updatedAt),
      };
      emit('update', violation);
    }
  } catch (error) {
    console.error('Error resolving violation:', error);
  }
};

const ignoreViolation = async () => {
  if (!props.violation || !confirm('Ignore this violation?')) return;

  try {
    const response = await fetch(`http://localhost:3001/api/violations/${props.violation.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'ignored',
        ignoredAt: new Date().toISOString(),
        ignoredBy: currentUser.value,
      }),
    });

    if (response.ok) {
      const updatedViolation = await response.json();
      // Convert date strings to Date objects
      const violation = {
        ...updatedViolation,
        detectedAt: new Date(updatedViolation.detectedAt),
        resolvedAt: updatedViolation.resolvedAt ? new Date(updatedViolation.resolvedAt) : undefined,
        ignoredAt: updatedViolation.ignoredAt ? new Date(updatedViolation.ignoredAt) : undefined,
        createdAt: new Date(updatedViolation.createdAt),
        updatedAt: new Date(updatedViolation.updatedAt),
      };
      emit('update', violation);
    }
  } catch (error) {
    console.error('Error ignoring violation:', error);
  }
};

const viewRelatedViolation = (id: string) => {
  emit('viewRelated', id);
};

const loadTickets = async () => {
  if (!props.violation) return;
  
  try {
    const response = await fetch(`/api/ticketing/tickets?violationId=${props.violation.id}`);
    if (response.ok) {
      tickets.value = await response.json();
    }
  } catch (error) {
    console.error('Error loading tickets:', error);
  }
};

const loadIntegrations = async () => {
  try {
    const response = await fetch('/api/ticketing/integrations');
    if (response.ok) {
      integrations.value = await response.json();
      hasEnabledIntegration.value = integrations.value.some(i => i.enabled);
    }
  } catch (error) {
    console.error('Error loading integrations:', error);
  }
};

const createTicket = async () => {
  if (!props.violation || !hasEnabledIntegration.value) return;
  
  const enabledIntegration = integrations.value.find(i => i.enabled);
  if (!enabledIntegration) {
    alert('No enabled ticketing integration found. Please configure one in Admin > Ticketing Integrations.');
    return;
  }

  creatingTicket.value = true;
  try {
    const priority = mapSeverityToPriority(props.violation.severity);
    const description = buildTicketDescription(props.violation);

    const response = await fetch(`/api/ticketing/integrations/${enabledIntegration.id}/tickets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        violationId: props.violation.id,
        title: props.violation.title,
        description,
        priority,
        assignee: props.violation.assignedTo,
      }),
    });

    if (response.ok) {
      const ticket = await response.json();
      tickets.value.push(ticket);
      alert(`Ticket created: ${ticket.externalId}`);
    } else {
      const error = await response.json();
      alert(error.message || 'Failed to create ticket');
    }
  } catch (error) {
    console.error('Error creating ticket:', error);
    alert('Failed to create ticket');
  } finally {
    creatingTicket.value = false;
  }
};

const mapSeverityToPriority = (severity: string): string => {
  const mapping: Record<string, string> = {
    critical: 'highest',
    high: 'high',
    medium: 'medium',
    low: 'low',
  };
  return mapping[severity] || 'medium';
};

const buildTicketDescription = (violation: ViolationEntity): string => {
  let description = violation.description || '';

  if (violation.policyName) {
    description += `\n\nPolicy: ${violation.policyName}`;
  }

  if (violation.remediationSuggestions && violation.remediationSuggestions.length > 0) {
    description += '\n\nRemediation Suggestions:';
    violation.remediationSuggestions.forEach((suggestion, index) => {
      description += `\n${index + 1}. ${suggestion}`;
    });
  }

  if (violation.resource) {
    description += `\n\nAffected Resource: ${violation.resource}`;
  }

  return description;
};

const formatTicketStatus = (status: string): string => {
  const statusMap: Record<string, string> = {
    open: 'Open',
    in_progress: 'In Progress',
    resolved: 'Resolved',
    closed: 'Closed',
  };
  return statusMap[status] || status;
};

watch(() => props.show, (newVal) => {
  if (newVal) {
    newComment.value = '';
    loadTickets();
    loadIntegrations();
  }
});

onMounted(() => {
  if (props.show) {
    loadTickets();
    loadIntegrations();
  }
});
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
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
  width: 28px;
  height: 28px;
}

.icon-critical {
  color: #fc8181;
}

.icon-high {
  color: #fbbf24;
}

.icon-medium {
  color: #4facfe;
}

.icon-low {
  color: #718096;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 8px;
  transition: all 0.2s;
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
  flex: 1;
  overflow-y: auto;
}

.badges-section {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
}

.severity-badge,
.status-badge {
  padding: 6px 16px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
}

.badge-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.badge-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.badge-medium {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.badge-low {
  background: rgba(113, 128, 150, 0.2);
  color: #718096;
}

.status-open {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-in-progress {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-resolved {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-ignored {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.detail-section {
  margin-bottom: 32px;
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.info-value {
  font-size: 0.9rem;
  color: #ffffff;
}

.description-text {
  font-size: 0.95rem;
  color: #a0aec0;
  line-height: 1.6;
}

.resources-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.resource-badge {
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  font-size: 0.875rem;
  color: #4facfe;
}

.test-details {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
}

.test-details pre {
  margin: 0;
  color: #a0aec0;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
}

.suggestions-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.suggestions-list li {
  padding: 8px 0;
  color: #a0aec0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.suggestions-list li:last-child {
  border-bottom: none;
}

.remediation-status {
  color: #a0aec0;
  font-size: 0.95rem;
}

.timeline {
  position: relative;
  padding-left: 24px;
}

.timeline-item {
  position: relative;
  padding-bottom: 24px;
}

.timeline-item:not(:last-child)::before {
  content: '';
  position: absolute;
  left: 7px;
  top: 24px;
  bottom: -24px;
  width: 2px;
  background: rgba(79, 172, 254, 0.2);
}

.timeline-marker {
  position: absolute;
  left: -24px;
  top: 4px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #4facfe;
  border: 2px solid #1a1f2e;
}

.timeline-content {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 12px 16px;
}

.timeline-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.timeline-type {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
  text-transform: capitalize;
}

.timeline-time {
  font-size: 0.75rem;
  color: #718096;
}

.timeline-description {
  font-size: 0.9rem;
  color: #ffffff;
  margin-bottom: 4px;
}

.timeline-actor {
  font-size: 0.75rem;
  color: #718096;
}

.comments-list {
  margin-bottom: 16px;
}

.comment-item {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 12px;
}

.comment-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.comment-author {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
}

.comment-date {
  font-size: 0.75rem;
  color: #718096;
}

.comment-content {
  font-size: 0.9rem;
  color: #a0aec0;
  line-height: 1.5;
  margin: 0;
}

.no-comments {
  text-align: center;
  padding: 24px;
  color: #718096;
  font-size: 0.9rem;
}

.add-comment {
  margin-top: 16px;
}

.comment-input {
  width: 100%;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-family: inherit;
  resize: vertical;
  margin-bottom: 12px;
}

.comment-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.comment-submit-btn {
  padding: 10px 20px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.comment-submit-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.comment-submit-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.related-violations {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.related-violation-link {
  padding: 8px 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.related-violation-link:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.modal-actions {
  display: flex;
  gap: 12px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
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

.resolve-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.ignore-btn:hover {
  background: rgba(156, 163, 175, 0.1);
  border-color: rgba(156, 163, 175, 0.5);
  color: #9ca3af;
}

.action-icon {
  width: 18px;
  height: 18px;
}

.tickets-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.ticket-link {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  background: rgba(79, 172, 254, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  text-decoration: none;
  color: #fff;
  transition: all 0.2s;
}

.ticket-link:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.ticket-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
  flex-shrink: 0;
}

.ticket-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.ticket-id {
  font-size: 0.9rem;
  font-weight: 600;
  color: #fff;
}

.ticket-status {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: 4px;
  display: inline-block;
  width: fit-content;
}

.status-open {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-in_progress {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-resolved {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-closed {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.external-icon {
  width: 16px;
  height: 16px;
  color: #718096;
  flex-shrink: 0;
}

.ticket-btn {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.3);
}

.ticket-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.2);
}

.ticket-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

