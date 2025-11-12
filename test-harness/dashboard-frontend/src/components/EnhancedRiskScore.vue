<template>
  <div class="enhanced-risk-score">
    <div class="risk-score-header">
      <h3>Enhanced Risk Score</h3>
      <button v-if="!expanded" @click="expanded = true" class="expand-btn">
        <ChevronDown class="icon" />
        Show Details
      </button>
      <button v-else @click="expanded = false" class="expand-btn">
        <ChevronUp class="icon" />
        Hide Details
      </button>
    </div>

    <div class="risk-score-summary">
      <div class="score-card">
        <div class="score-label">Adjusted Score</div>
        <div class="score-value" :class="getScoreClass(riskScore?.adjustedScore || 0)">
          {{ (riskScore?.adjustedScore || 0).toFixed(1) }}
        </div>
        <div class="score-base">Base: {{ (riskScore?.baseScore || 0).toFixed(1) }}</div>
      </div>
      <div class="score-card">
        <div class="score-label">Priority</div>
        <div class="score-value" :class="getScoreClass(riskScore?.priority || 0)">
          {{ (riskScore?.priority || 0).toFixed(1) }}
        </div>
        <div class="score-age">Age: {{ riskScore?.age || 0 }} days</div>
      </div>
      <div class="score-card" v-if="riskScore?.trend">
        <div class="score-label">Trend</div>
        <div class="trend-indicator" :class="`trend-${riskScore.trend}`">
          <TrendingUp v-if="riskScore.trend === 'increasing'" class="trend-icon" />
          <TrendingDown v-else-if="riskScore.trend === 'decreasing'" class="trend-icon" />
          <Minus v-else class="trend-icon" />
          {{ riskScore.trend }}
        </div>
      </div>
    </div>

    <div v-if="expanded && riskScore" class="risk-score-details">
      <!-- Risk Factors -->
      <div class="factors-section">
        <h4>Risk Factors</h4>
        <div class="factors-grid">
          <div class="factor-item">
            <span class="factor-label">Severity</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.severity}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.severity.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Exploitability</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.exploitability}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.exploitability.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Asset Criticality</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.assetCriticality}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.assetCriticality.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Exposure</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.exposure}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.exposure.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Data Sensitivity</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.dataSensitivity}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.dataSensitivity.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Compliance Impact</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.complianceImpact}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.complianceImpact.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Business Impact</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.businessImpact}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.businessImpact.toFixed(0) }}</span>
          </div>
          <div class="factor-item">
            <span class="factor-label">Remediation Complexity</span>
            <div class="factor-bar">
              <div class="factor-fill" :style="{ width: `${riskScore.factors.remediationComplexity}%` }"></div>
            </div>
            <span class="factor-value">{{ riskScore.factors.remediationComplexity.toFixed(0) }}</span>
          </div>
        </div>
      </div>

      <!-- Threat Intelligence -->
      <div v-if="riskScore.threatIntelligence" class="threat-section">
        <h4>Threat Intelligence</h4>
        <div class="threat-grid">
          <div class="threat-item" :class="{ active: riskScore.threatIntelligence.activeExploits }">
            <AlertTriangle class="threat-icon" />
            <span>Active Exploits</span>
            <span class="threat-status">{{ riskScore.threatIntelligence.activeExploits ? 'Yes' : 'No' }}</span>
          </div>
          <div class="threat-item" :class="{ active: riskScore.threatIntelligence.exploitInWild }">
            <ShieldAlert class="threat-icon" />
            <span>Exploit in Wild</span>
            <span class="threat-status">{{ riskScore.threatIntelligence.exploitInWild ? 'Yes' : 'No' }}</span>
          </div>
          <div class="threat-item" :class="{ active: riskScore.threatIntelligence.ransomware }">
            <Lock class="threat-icon" />
            <span>Ransomware</span>
            <span class="threat-status">{{ riskScore.threatIntelligence.ransomware ? 'Yes' : 'No' }}</span>
          </div>
          <div class="threat-item">
            <Users class="threat-icon" />
            <span>Threat Actor Interest</span>
            <span class="threat-status" :class="`interest-${riskScore.threatIntelligence.threatActorInterest}`">
              {{ riskScore.threatIntelligence.threatActorInterest }}
            </span>
          </div>
        </div>
      </div>

      <!-- Priority Reason -->
      <div v-if="riskScore.priorityReason" class="priority-reason">
        <h4>Priority Reason</h4>
        <p>{{ riskScore.priorityReason }}</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { ChevronDown, ChevronUp, TrendingUp, TrendingDown, Minus, AlertTriangle, ShieldAlert, Lock, Users } from 'lucide-vue-next';

const props = defineProps<{
  riskScore?: {
    baseScore: number;
    adjustedScore: number;
    factors: {
      severity: number;
      exploitability: number;
      assetCriticality: number;
      exposure: number;
      dataSensitivity: number;
      complianceImpact: number;
      businessImpact: number;
      remediationComplexity: number;
    };
    age: number;
    trend: 'increasing' | 'stable' | 'decreasing';
    threatIntelligence?: {
      activeExploits: boolean;
      exploitInWild: boolean;
      ransomware: boolean;
      threatActorInterest: 'high' | 'medium' | 'low';
    };
    priority: number;
    priorityReason: string;
  };
}>();

const expanded = ref(false);

const getScoreClass = (score: number): string => {
  if (score >= 75) return 'score-high';
  if (score >= 50) return 'score-medium';
  return 'score-low';
};
</script>

<style scoped>
.enhanced-risk-score {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 24px;
}

.risk-score-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.risk-score-header h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.expand-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.expand-btn:hover {
  background: rgba(79, 172, 254, 0.1);
}

.expand-btn .icon {
  width: 16px;
  height: 16px;
}

.risk-score-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}

.score-card {
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.score-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.score-value {
  font-size: 2rem;
  font-weight: 700;
  margin-bottom: 4px;
}

.score-value.score-high {
  color: #fc8181;
}

.score-value.score-medium {
  color: #fbbf24;
}

.score-value.score-low {
  color: #22c55e;
}

.score-base,
.score-age {
  font-size: 0.75rem;
  color: #718096;
}

.trend-indicator {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  font-size: 0.875rem;
  font-weight: 500;
  text-transform: capitalize;
}

.trend-indicator.trend-increasing {
  color: #fc8181;
}

.trend-indicator.trend-decreasing {
  color: #22c55e;
}

.trend-indicator.trend-stable {
  color: #a0aec0;
}

.trend-icon {
  width: 16px;
  height: 16px;
}

.risk-score-details {
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  padding-top: 20px;
}

.factors-section,
.threat-section,
.priority-reason {
  margin-bottom: 24px;
}

.factors-section h4,
.threat-section h4,
.priority-reason h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.factors-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.factor-item {
  display: grid;
  grid-template-columns: 120px 1fr 60px;
  align-items: center;
  gap: 12px;
}

.factor-label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
}

.factor-bar {
  height: 8px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 4px;
  overflow: hidden;
}

.factor-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.factor-value {
  font-size: 0.875rem;
  color: #ffffff;
  font-weight: 600;
  text-align: right;
}

.threat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.threat-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  transition: all 0.2s;
}

.threat-item.active {
  border-color: #fc8181;
  background: rgba(252, 129, 129, 0.1);
}

.threat-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
}

.threat-item.active .threat-icon {
  color: #fc8181;
}

.threat-item span:not(.threat-status) {
  flex: 1;
  font-size: 0.875rem;
  color: #ffffff;
}

.threat-status {
  font-size: 0.875rem;
  font-weight: 600;
  padding: 4px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.threat-status.interest-high {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.threat-status.interest-medium {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.threat-status.interest-low {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.priority-reason p {
  font-size: 0.9rem;
  color: #ffffff;
  line-height: 1.6;
  margin: 0;
  padding: 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  border-left: 3px solid #4facfe;
}
</style>

