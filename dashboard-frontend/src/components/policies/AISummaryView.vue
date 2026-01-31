<template>
  <div class="ai-summary-view">
    <div class="summary-header">
      <h2>Policy Change Summary</h2>
      <div class="date-range-selector">
        <input type="date" v-model="startDate" />
        <span>to</span>
        <input type="date" v-model="endDate" />
        <button @click="generateSummary" :disabled="loading" class="btn-primary">
          Generate Summary
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Generating summary...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="generateSummary" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="summary" class="summary-content" ref="summaryContentRef">
      <div class="summary-tabs">
        <button @click="summaryType = 'executive'" :class="['tab-btn', { active: summaryType === 'executive' }]">
          Executive Summary
        </button>
        <button @click="summaryType = 'detailed'" :class="['tab-btn', { active: summaryType === 'detailed' }]">
          Detailed Summary
        </button>
      </div>

      <ExecutiveSummary v-if="summaryType === 'executive' && summary.executive" :summary="summary.executive" />
      <DetailedSummary v-if="summaryType === 'detailed' && summary.detailed" :summary="summary.detailed" />

      <div class="summary-actions">
        <button @click="exportPDF" :disabled="exportingPDF" class="btn-secondary">
          {{ exportingPDF ? 'Generating PDF...' : 'Export PDF' }}
        </button>
        <button @click="exportHTML" class="btn-secondary">Export HTML</button>
        <button @click="exportJSON" class="btn-secondary">Export JSON</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, nextTick } from 'vue';
import { AlertTriangle } from 'lucide-vue-next';
import ExecutiveSummary from './ExecutiveSummary.vue';
import DetailedSummary from './DetailedSummary.vue';
import axios from 'axios';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

const startDate = ref(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]);
const endDate = ref(new Date().toISOString().split('T')[0]);
const summaryType = ref<'executive' | 'detailed'>('executive');
const loading = ref(false);
const error = ref<string | null>(null);
const exportingPDF = ref(false);
const summary = ref<{
  executive?: any;
  detailed?: any;
} | null>(null);

const summaryContentRef = ref<HTMLElement | null>(null);

// Debounce function for performance
const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

const generateSummary = async () => {
  // Validate date range
  const start = new Date(startDate.value);
  const end = new Date(endDate.value);

  if (isNaN(start.getTime()) || isNaN(end.getTime())) {
    error.value = 'Please select valid dates';
    return;
  }

  if (start > end) {
    error.value = 'Start date must be before end date';
    return;
  }

  // Check if date range is too large (performance optimization)
  const daysDiff = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
  if (daysDiff > 365) {
    error.value = 'Date range cannot exceed 365 days. Please select a smaller range.';
    return;
  }

  loading.value = true;
  error.value = null;

  try {
    const [executiveResponse, detailedResponse] = await Promise.all([
      axios.get('/api/policies/summaries/executive', {
        params: { startDate: startDate.value, endDate: endDate.value },
        timeout: 30000, // 30 second timeout
      }),
      axios.get('/api/policies/summaries/detailed', {
        params: { startDate: startDate.value, endDate: endDate.value },
        timeout: 30000,
      })
    ]);

    summary.value = {
      executive: executiveResponse.data,
      detailed: detailedResponse.data,
    };
  } catch (err: any) {
    if (err.code === 'ECONNABORTED') {
      error.value = 'Request timed out. The summary is taking longer than expected. Please try again or select a smaller date range.';
    } else if (err.response?.status === 400) {
      error.value = err.response?.data?.message || 'Invalid request. Please check your date range.';
    } else if (err.response?.status === 500) {
      error.value = 'Server error occurred while generating summary. Please try again later.';
    } else {
      error.value = err.response?.data?.message || err.message || 'Failed to generate summary. Please try again.';
    }
    console.error('Error generating summary:', err);
  } finally {
    loading.value = false;
  }
};

const exportPDF = async () => {
  if (!summary.value) return;
  
  exportingPDF.value = true;
  
  try {
    await nextTick();
    
    // Get the summary content element
    const contentElement = summaryContentRef.value || document.querySelector('.summary-content');
    if (!contentElement) {
      throw new Error('Summary content not found');
    }

    // Create canvas from HTML
    const canvas = await html2canvas(contentElement as HTMLElement, {
      scale: 2,
      useCORS: true,
      logging: false,
      backgroundColor: '#ffffff',
    });

    const imgData = canvas.toDataURL('image/png');
    
    // Calculate PDF dimensions
    const imgWidth = canvas.width;
    const imgHeight = canvas.height;
    const pdfWidth = 210; // A4 width in mm
    const pdfHeight = (imgHeight * pdfWidth) / imgWidth;
    
    // Create PDF
    const pdf = new jsPDF('p', 'mm', 'a4');
    
    // Add header
    pdf.setFontSize(18);
    pdf.text('Policy Change Summary', 105, 15, { align: 'center' });
    pdf.setFontSize(10);
    pdf.setTextColor(100, 100, 100);
    pdf.text(
      `Generated: ${new Date().toLocaleDateString()} | Period: ${startDate.value} to ${endDate.value}`,
      105,
      22,
      { align: 'center' }
    );
    
    // Add content
    let heightLeft = pdfHeight;
    let position = 30;
    const pageHeight = 297; // A4 height in mm
    
    // Add image
    pdf.addImage(imgData, 'PNG', 0, position, pdfWidth, pdfHeight);
    heightLeft -= pageHeight;
    
    // Add new pages if needed
    while (heightLeft >= 0) {
      position = heightLeft - pdfHeight;
      pdf.addPage();
      pdf.addImage(imgData, 'PNG', 0, position, pdfWidth, pdfHeight);
      heightLeft -= pageHeight;
    }
    
    // Add footer on each page
    const totalPages = pdf.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      pdf.setPage(i);
      pdf.setFontSize(8);
      pdf.setTextColor(150, 150, 150);
      pdf.text(
        `Page ${i} of ${totalPages}`,
        105,
        287,
        { align: 'center' }
      );
    }
    
    // Save PDF
    pdf.save(`policy-summary-${new Date().toISOString().split('T')[0]}.pdf`);
  } catch (err: any) {
    console.error('Error exporting PDF:', err);
    error.value = 'Failed to export PDF: ' + (err.message || 'Unknown error');
  } finally {
    exportingPDF.value = false;
  }
};

const exportHTML = () => {
  if (!summary.value) return;
  
  const currentSummary = summaryType.value === 'executive' 
    ? summary.value.executive 
    : summary.value.detailed;
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Policy Summary Report</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
          padding: 40px;
          background: #f5f5f5;
          color: #333;
          line-height: 1.6;
        }
        .container {
          max-width: 1200px;
          margin: 0 auto;
          background: white;
          padding: 40px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
          border-bottom: 3px solid #4a90e2;
          padding-bottom: 20px;
          margin-bottom: 30px;
        }
        h1 {
          color: #2c3e50;
          font-size: 32px;
          margin-bottom: 10px;
        }
        .meta {
          color: #7f8c8d;
          font-size: 14px;
        }
        .section {
          margin: 30px 0;
          padding: 20px;
          background: #f9f9f9;
          border-left: 4px solid #4a90e2;
          border-radius: 4px;
        }
        .section h2 {
          color: #2c3e50;
          font-size: 24px;
          margin-bottom: 15px;
        }
        .metrics-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 15px;
          margin: 20px 0;
        }
        .metric-card {
          padding: 15px;
          background: white;
          border: 1px solid #e0e0e0;
          border-radius: 4px;
        }
        .metric-label {
          font-size: 12px;
          color: #7f8c8d;
          text-transform: uppercase;
          margin-bottom: 5px;
        }
        .metric-value {
          font-size: 24px;
          font-weight: bold;
          color: #2c3e50;
        }
        ul {
          margin-left: 20px;
          margin-top: 10px;
        }
        li {
          margin-bottom: 8px;
        }
        .footer {
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #e0e0e0;
          text-align: center;
          color: #7f8c8d;
          font-size: 12px;
        }
        @media print {
          body { background: white; padding: 0; }
          .container { box-shadow: none; }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Policy Change Summary</h1>
          <div class="meta">
            Generated: ${new Date().toLocaleDateString()} | 
            Period: ${startDate.value} to ${endDate.value} | 
            Type: ${summaryType.value === 'executive' ? 'Executive Summary' : 'Detailed Summary'}
          </div>
        </div>
        <div class="content">
          ${formatSummaryForHTML(currentSummary)}
        </div>
        <div class="footer">
          Generated by Heimdall Policy Builder
        </div>
      </div>
    </body>
    </html>
  `;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `policy-summary-${new Date().toISOString().split('T')[0]}.html`;
  a.click();
  URL.revokeObjectURL(url);
};

const formatSummaryForHTML = (summary: any): string => {
  if (!summary) return '<p>No summary data available</p>';
  
  let html = '';
  
  if (summary.summary) {
    html += `<div class="section"><h2>Summary</h2><p>${summary.summary.replace(/\n/g, '<br>')}</p></div>`;
  }
  
  if (summary.keyMetrics) {
    html += '<div class="section"><h2>Key Metrics</h2><div class="metrics-grid">';
    Object.entries(summary.keyMetrics).forEach(([key, value]) => {
      html += `
        <div class="metric-card">
          <div class="metric-label">${formatKey(key)}</div>
          <div class="metric-value">${value}</div>
        </div>
      `;
    });
    html += '</div></div>';
  }
  
  if (summary.keyChanges && summary.keyChanges.length > 0) {
    html += '<div class="section"><h2>Key Changes</h2><ul>';
    summary.keyChanges.forEach((change: string) => {
      html += `<li>${change}</li>`;
    });
    html += '</ul></div>';
  }
  
  if (summary.impact) {
    html += '<div class="section"><h2>Impact</h2>';
    html += `<p><strong>Resources Affected:</strong> ${summary.impact.resourcesAffected || 0}</p>`;
    html += `<p><strong>Applications Affected:</strong> ${summary.impact.applicationsAffected || 0}</p>`;
    html += `<p><strong>Estimated Effort:</strong> ${summary.impact.estimatedEffort || 'N/A'}</p>`;
    html += '</div>';
  }
  
  if (summary.recommendations && summary.recommendations.length > 0) {
    html += '<div class="section"><h2>Recommendations</h2><ul>';
    summary.recommendations.forEach((rec: string) => {
      html += `<li>${rec}</li>`;
    });
    html += '</ul></div>';
  }
  
  // Handle detailed summary format
  if (summary.policyChanges) {
    html += '<div class="section"><h2>Policy Changes</h2>';
    summary.policyChanges.forEach((change: any) => {
      html += `
        <div style="margin-bottom: 20px; padding: 15px; background: white; border-left: 3px solid #4a90e2;">
          <h3>${change.policyName}</h3>
          <p><strong>Type:</strong> ${change.changeType}</p>
          ${change.changes && change.changes.length > 0 ? `<p><strong>Changes:</strong><ul>${change.changes.map((c: string) => `<li>${c}</li>`).join('')}</ul></p>` : ''}
        </div>
      `;
    });
    html += '</div>';
  }
  
  return html;
};

const formatKey = (key: string): string => {
  return key
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .trim();
};

const exportJSON = () => {
  if (!summary.value) return;

  const blob = new Blob([JSON.stringify(summary.value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `policy-summary-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
};
</script>

<style scoped>
.ai-summary-view {
  display: flex;
  flex-direction: column;
  height: 100%;
  padding: var(--spacing-lg);
}

.summary-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.summary-header h2 {
  margin: 0;
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
}

.date-range-selector {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.date-range-selector input[type="date"] {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
}

.summary-tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-btn {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.tab-btn.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.summary-content {
  flex: 1;
  overflow-y: auto;
}

.summary-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.btn-primary,
.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-primary);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-hover);
}

.loading-state,
.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  min-height: 400px;
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin-bottom: var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: 500;
}
</style>
