<template>
  <div class="roi-metrics">
    <h3 class="section-title">ROI Metrics</h3>
    <div class="roi-grid">
      <div class="roi-card">
        <div class="roi-icon cost-savings">
          <DollarSign class="icon" />
        </div>
        <div class="roi-content">
          <div class="roi-label">Cost Savings</div>
          <div class="roi-value">${{ costSavings.toLocaleString() }}</div>
          <div class="roi-description">Prevented incidents & reduced risk</div>
        </div>
      </div>
      <div class="roi-card">
        <div class="roi-icon time-saved">
          <Clock class="icon" />
        </div>
        <div class="roi-content">
          <div class="roi-label">Time Saved</div>
          <div class="roi-value">{{ timeSaved }} hours</div>
          <div class="roi-description">Automation & efficiency gains</div>
        </div>
      </div>
      <div class="roi-card">
        <div class="roi-icon risk-reduction">
          <Shield class="icon" />
        </div>
        <div class="roi-content">
          <div class="roi-label">Risk Reduction</div>
          <div class="roi-value">{{ riskReduction }}%</div>
          <div class="roi-description">Overall risk score improvement</div>
        </div>
      </div>
      <div class="roi-card">
        <div class="roi-icon compliance-gain">
          <TrendingUp class="icon" />
        </div>
        <div class="roi-content">
          <div class="roi-label">Compliance Gain</div>
          <div class="roi-value">+{{ complianceGain }}%</div>
          <div class="roi-description">Compliance score improvement</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { DollarSign, Clock, Shield, TrendingUp } from 'lucide-vue-next';

defineProps<{
  costSavings: number;
  timeSaved: number;
  riskReduction: number;
  complianceGain: number;
}>();
</script>

<style scoped>
.roi-metrics {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 20px;
}

.roi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
}

.roi-card {
  display: flex;
  gap: 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 12px;
  padding: 20px;
  transition: all 0.3s;
}

.roi-card:hover {
  border-color: rgba(79, 172, 254, 0.3);
  transform: translateY(-2px);
}

.roi-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.roi-icon.cost-savings {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.roi-icon.time-saved {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.roi-icon.risk-reduction {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.roi-icon.compliance-gain {
  background: rgba(139, 92, 246, 0.2);
  color: #8b5cf6;
}

.roi-icon .icon {
  width: 24px;
  height: 24px;
}

.roi-content {
  flex: 1;
}

.roi-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 4px;
}

.roi-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 4px;
}

.roi-description {
  font-size: 0.75rem;
  color: #718096;
}
</style>

