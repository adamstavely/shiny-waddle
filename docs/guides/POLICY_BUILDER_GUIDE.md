# Policy Builder User Guide

**Version:** 4.0  
**Status:** ✅ Phase 4 Complete  
**Last Updated:** January 31, 2026

---

## Overview

The Policy Builder is a comprehensive, production-ready system for creating, managing, and analyzing access control policies. It provides visual tools, AI-powered insights, automation capabilities, and collaboration features to help teams manage policies effectively.

---

## Getting Started

### Accessing the Policy Builder

1. Navigate to **Policies** → **Access Control** in the main navigation
2. Click **"Create Policy"** to start building a new policy
3. Or select an existing policy to edit

### Key Features

- **Visual Builder**: Drag-and-drop interface for creating policies
- **AI Summaries**: Generate intelligent summaries of policy changes
- **Gap Analysis**: Identify compliance gaps automatically
- **Approval Workflows**: Multi-stage approval for policy changes
- **Comments & Collaboration**: Team collaboration with threaded comments

---

## Core Features

### 1. Visual Policy Builder

The visual builder provides an intuitive drag-and-drop interface for creating RBAC and ABAC policies.

**Access:** Create/Edit Policy → Visual Builder tab

**Features:**
- Drag-and-drop rule creation
- Visual condition builder
- Real-time JSON preview
- Import/export JSON
- Policy validation

**How to Use:**
1. Drag elements from the palette to the workspace
2. Configure rules and conditions using the form inputs
3. Preview the JSON output in real-time
4. Validate and save your policy

### 2. Policy Comparison

Compare different versions of policies to see what changed.

**Access:** Policy Detail → Versions tab → Compare

**Features:**
- Side-by-side comparison
- Highlighted differences
- Change summary
- Version history

### 3. Gap Analysis

Identify compliance gaps and enforcement issues.

**Access:** Policy Detail → Gap Analysis tab

**Features:**
- Automatic gap detection
- Severity classification
- Remediation guidance
- Gap tracking

### 4. AI-Powered Summaries

Generate intelligent summaries of policy changes and compliance status.

**Access:** Policies → Summaries

**Features:**
- Executive summaries
- Detailed summaries
- Compliance summaries
- PDF/HTML export
- Date range selection

**How to Use:**
1. Navigate to **Policies** → **Summaries**
2. Select date range
3. Click **"Generate Summary"**
4. Export as PDF or HTML

### 5. Policy Recommendations

Get AI-generated recommendations for improving your policies.

**Access:** Policy Detail → Recommendations

**Features:**
- AI-powered suggestions
- Impact assessment
- Effort estimation
- Confidence scoring
- Apply/dismiss recommendations

### 6. Natural Language Queries

Ask questions about policies in plain English.

**Access:** Policies → Summaries → Query tab

**Example Queries:**
- "What policies affect data classification?"
- "Show me all policies with high-risk gaps"
- "Which policies were modified last week?"

### 7. Compliance Trends

View compliance trends over time with interactive charts.

**Access:** Policies → Compliance Dashboard

**Features:**
- Interactive charts
- Multiple time ranges (7d, 30d, 90d, 1y)
- Export charts
- Trend analysis

### 8. Scheduled Reports

Automate report generation and delivery.

**Access:** Policies → Compliance Dashboard → Scheduled Reports

**Features:**
- Daily/weekly/monthly scheduling
- Multiple report types
- Email recipients
- Manual execution
- Report history

**How to Create:**
1. Click **"Create Scheduled Report"**
2. Configure name, type, schedule, and recipients
3. Enable/disable as needed
4. Reports run automatically or manually

### 9. Automation Rules

Automate policy change workflows and gap remediation.

**Access:** Policies → Automation Rules (via API)

**Features:**
- Configurable triggers
- Multiple action types
- Approval requirements
- Auto-fix capabilities

**Action Types:**
- Auto-fix: Automatically fix simple gaps
- Notify: Send notifications
- Create Ticket: Create tickets in ticketing system
- Escalate: Escalate to managers

### 10. Policy Comments

Collaborate on policies with threaded comments.

**Access:** Policy Detail → Comments tab

**Features:**
- Threaded comments
- @mentions
- Edit/delete comments
- Comment history

**How to Use:**
1. Navigate to policy detail
2. Click **Comments** tab
3. Add comment with @mentions
4. Reply to existing comments

### 11. Approval Workflows

Multi-stage approval for policy changes.

**Access:** Policy Detail → Approvals tab

**Features:**
- Multi-stage approvals
- Required approvers
- Approval/rejection tracking
- Comments on approvals

**How to Use:**
1. Click **"Request Approval"**
2. Configure approval stages
3. Approvers receive notifications
4. Track approval status

---

## Advanced Features

### PDF/HTML Export

Export policy summaries and reports in multiple formats.

**Supported Formats:**
- PDF (multi-page with headers/footers)
- HTML (print-friendly)

**How to Export:**
1. Generate a summary
2. Click **"Export PDF"** or **"Export HTML"**
3. File downloads automatically

### Caching

Summaries and recommendations are cached for performance.

**Cache Duration:**
- Summaries: 1 hour
- Recommendations: 30 minutes
- Compliance analysis: 1 hour

**Cache Invalidation:**
- Automatic on policy changes
- Manual via API

### LLM Integration

AI features use Large Language Models for enhanced summaries and recommendations.

**Supported Providers:**
- OpenAI
- Anthropic
- Azure OpenAI
- Template-based fallback (when LLM unavailable)

**Configuration:**
Set environment variables:
```bash
LLM_PROVIDER=openai
LLM_API_KEY=your_key
LLM_MODEL=gpt-4-turbo-preview
```

---

## Best Practices

### Policy Creation
1. Start with templates when available
2. Use visual builder for complex policies
3. Validate before saving
4. Document policy purpose in description

### Gap Analysis
1. Review gaps regularly
2. Prioritize high-severity gaps
3. Use automated remediation for low-risk gaps
4. Track remediation progress

### Collaboration
1. Use comments for discussions
2. Request approvals for significant changes
3. Mention relevant team members
4. Document decisions in comments

### Reporting
1. Schedule regular reports
2. Customize report recipients
3. Review trends regularly
4. Export reports for documentation

---

## Troubleshooting

### Summary Generation Fails
- Check date range (max 365 days)
- Verify LLM configuration (if using AI)
- Check API connectivity
- Review error messages

### Recommendations Not Showing
- Ensure policy has compliance data
- Check LLM service status
- Verify cache isn't stale
- Review API logs

### Approval Workflow Issues
- Verify approver permissions
- Check stage configuration
- Review approval history
- Ensure notifications are enabled

### Performance Issues
- Check cache status
- Review date range size
- Verify API response times
- Check browser console for errors

---

## API Reference

For detailed API documentation, see:
- [API Documentation](../api/API.md)
- [Policy Builder Phase 4 Plan](../development/POLICY_BUILDER_PHASE4_IMPLEMENTATION_PLAN.md)

---

## Related Documentation

- [Policy Creation Guide](./POLICY_CREATION_GUIDE.md) - Creating RBAC/ABAC policies
- [Phase 4 Complete Summary](../development/PHASE4_COMPLETE_SUMMARY.md) - Implementation details
- [Phase 4 Implementation Plan](../development/POLICY_BUILDER_PHASE4_IMPLEMENTATION_PLAN.md) - Technical details

---

**Status:** ✅ Production Ready  
**Support:** See main [README](../../README.md) for support information
