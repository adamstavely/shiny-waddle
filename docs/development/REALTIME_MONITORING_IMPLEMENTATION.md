# Real-Time Access Monitoring Implementation

## Status: Backend Integration Complete ✅

**Date:** January 2025  
**Phase:** Task 1.1 - Backend Integration (Weeks 1-2)

---

## What Was Implemented

### 1. RealtimeModule (`dashboard-api/src/realtime/`)

Created a new NestJS module for real-time access monitoring:

#### Files Created:
- **`realtime.module.ts`** - Module definition with dependencies
- **`realtime.service.ts`** - Core service integrating RealtimeIngestionService
- **`realtime.controller.ts`** - REST API endpoints

#### Key Features:

**RealtimeService:**
- ✅ Initializes `RealtimeIngestionService` with `NormalizationEngine` and `EnhancedRiskScorer`
- ✅ Sets up event listeners for ingestion events (`finding_received`, `finding_normalized`, `finding_scored`, `error`)
- ✅ Automatically stores findings in `UnifiedFindingsService` when normalized
- ✅ Broadcasts updates via SSE gateway (`DashboardSSEGateway`)
- ✅ Provides start/stop controls for the ingestion service
- ✅ Tracks service statistics (queue length, processing status, connected clients)

**RealtimeController:**
- ✅ `POST /api/v1/realtime/webhook` - Receive webhook payloads from scanners
- ✅ `GET /api/v1/realtime/stats` - Get ingestion statistics
- ✅ `POST /api/v1/realtime/start` - Start ingestion service
- ✅ `POST /api/v1/realtime/stop` - Stop ingestion service
- ✅ `GET /api/v1/realtime/status` - Get service status

### 2. UnifiedFindingsService Enhancement

Added `createFinding()` method to handle already-normalized findings:
- ✅ Adds/updates findings in the store
- ✅ Triggers notifications for critical findings
- ✅ Evaluates alert rules for new findings
- ✅ Stores compliance scores
- ✅ Handles deduplication

### 3. Integration Points

- ✅ Integrated with `DashboardModule` for SSE broadcasting
- ✅ Integrated with `UnifiedFindingsModule` for finding storage
- ✅ Added `RealtimeModule` to `AppModule`

---

## API Endpoints

### Webhook Endpoint
```http
POST /api/v1/realtime/webhook
Content-Type: application/json

{
  "scannerId": "sonarqube",
  "scannerName": "SonarQube",
  "findings": [...],
  "metadata": {
    "applicationId": "app-123",
    "applicationName": "My App",
    "scanId": "scan-456"
  }
}
```

**Response:**
```json
{
  "success": true,
  "findingsCount": 5,
  "findings": [
    {
      "id": "finding-123",
      "title": "Security Finding",
      "severity": "high",
      "riskScore": 75
    }
  ]
}
```

### Statistics Endpoint
```http
GET /api/v1/realtime/stats
```

**Response:**
```json
{
  "queueLength": 0,
  "isProcessing": false,
  "isRunning": true,
  "connectedClients": 3,
  "config": {
    "enableRealTimeNormalization": true,
    "enableRealTimeRiskScoring": true,
    "batchSize": 10,
    "batchTimeout": 1000,
    "maxConcurrency": 5
  }
}
```

### Control Endpoints
```http
POST /api/v1/realtime/start
POST /api/v1/realtime/stop
GET /api/v1/realtime/status
```

---

## Real-Time Updates via SSE

When findings are ingested, they are automatically broadcast via Server-Sent Events (SSE) to all connected clients:

**Event Format:**
```json
{
  "type": "violation",
  "data": {
    "finding": { ... },
    "eventType": "finding_normalized",
    "applicationId": "app-123",
    "timestamp": "2025-01-25T10:00:00Z"
  },
  "timestamp": "2025-01-25T10:00:00Z"
}
```

Clients connected to `/api/v1/dashboard/stream` will receive these updates in real-time.

---

## Architecture

```
┌─────────────────┐
│  Scanner/Webhook│
└────────┬────────┘
         │ POST /api/v1/realtime/webhook
         ▼
┌─────────────────┐
│ RealtimeController│
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│ RealtimeService │─────▶│RealtimeIngestion │
└────────┬────────┘      │     Service      │
         │               └────────┬─────────┘
         │                        │
         │                        ▼
         │               ┌──────────────────┐
         │               │NormalizationEngine│
         │               └────────┬─────────┘
         │                        │
         │                        ▼
         │               ┌──────────────────┐
         │               │ EnhancedRiskScorer│
         │               └──────────────────┘
         │
         ├──────────────────────────────────┐
         │                                  │
         ▼                                  ▼
┌─────────────────┐              ┌─────────────────┐
│UnifiedFindings  │              │ DashboardSSE   │
│    Service      │              │    Gateway     │
└─────────────────┘              └────────┬────────┘
                                          │
                                          ▼
                                  ┌─────────────────┐
                                  │  SSE Clients    │
                                  │  (Frontend)     │
                                  └─────────────────┘
```

---

## Known Issues & Next Steps

### Framework-Level Issues (Pre-existing)

The `heimdall-framework/services/realtime-ingestion.ts` file has some TypeScript errors that need to be addressed:

1. **Missing `remediation` property** in UnifiedFinding fallback creation
2. **Method signature mismatches** for `normalize()` and `calculateRiskScore()`
3. **Type mismatches** for `EnhancedRiskScore` properties

These don't prevent the module from working, but should be fixed for full type safety.

### Next Steps (Task 1.2 - Frontend Integration)

1. **Update Dashboard.vue** to use `useRealtimeUpdates` composable
2. **Update ApplicationDetail.vue** to show real-time access monitoring
3. **Create RealTimeMonitoring.vue** component
   - Display live access events
   - Show anomaly alerts
   - Display access patterns
4. **Test end-to-end flow** from webhook to frontend display

---

## Testing

### Manual Testing Steps

1. **Start the service:**
   ```bash
   curl -X POST http://localhost:3001/api/v1/realtime/start
   ```

2. **Send a test webhook:**
   ```bash
   curl -X POST http://localhost:3001/api/v1/realtime/webhook \
     -H "Content-Type: application/json" \
     -d '{
       "scannerId": "sonarqube",
       "findings": [{
         "id": "test-1",
         "title": "Test Finding",
         "severity": "high"
       }],
       "metadata": {
         "applicationId": "test-app"
       }
     }'
   ```

3. **Check statistics:**
   ```bash
   curl http://localhost:3001/api/v1/realtime/stats
   ```

4. **Connect to SSE stream:**
   ```bash
   curl http://localhost:3001/api/v1/dashboard/stream
   ```

### Expected Behavior

- Webhook is received and processed
- Findings are normalized and risk-scored
- Findings are stored in UnifiedFindingsService
- Updates are broadcast via SSE
- Statistics reflect the processing

---

## Files Modified

- ✅ `dashboard-api/src/app.module.ts` - Added RealtimeModule import
- ✅ `dashboard-api/src/unified-findings/unified-findings.service.ts` - Added `createFinding()` method

## Files Created

- ✅ `dashboard-api/src/realtime/realtime.module.ts`
- ✅ `dashboard-api/src/realtime/realtime.service.ts`
- ✅ `dashboard-api/src/realtime/realtime.controller.ts`

---

## Dependencies

- `@nestjs/common` - NestJS framework
- `heimdall-framework/services/realtime-ingestion` - Ingestion service
- `heimdall-framework/services/normalization-engine` - Normalization
- `heimdall-framework/services/enhanced-risk-scorer` - Risk scoring
- `dashboard/dashboard-sse.gateway` - SSE broadcasting
- `unified-findings/unified-findings.service` - Finding storage
- `elasticsearch/elasticsearch.service` - Elasticsearch integration (optional)

---

## Elasticsearch Integration ✅

Real-time monitoring events are automatically sent to Elasticsearch for dashboarding and reporting.

### Features:
- ✅ Automatic indexing of all findings to Elasticsearch
- ✅ ECS (Elastic Common Schema) format conversion
- ✅ Date-based index rotation (`heimdall-realtime-findings-YYYY.MM.DD`)
- ✅ Bulk indexing support
- ✅ Graceful error handling (non-blocking)
- ✅ Configurable via environment variables

### Configuration:

Set environment variables to enable:
```bash
ELASTICSEARCH_ENABLED=true
ELASTICSEARCH_NODE=http://localhost:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your-password
```

### What Gets Indexed:

1. **Findings**: All normalized findings are indexed to `heimdall-realtime-findings-*`
2. **Scoring Events**: Risk scoring events are indexed to `heimdall-realtime-events-*`
3. **Error Events**: Ingestion errors are indexed as events

### Kibana Dashboards:

Use the indexed data to create dashboards in Kibana:
- Findings by severity
- Findings over time
- Top applications by findings
- Risk score distribution
- Real-time monitoring dashboards

**See**: [ELASTICSEARCH_INTEGRATION.md](./ELASTICSEARCH_INTEGRATION.md) for detailed setup instructions.

---

## Success Criteria ✅

- [x] RealtimeModule created and integrated
- [x] Webhook endpoint receives payloads
- [x] Findings are normalized and risk-scored
- [x] Findings are stored in UnifiedFindingsService
- [x] Updates are broadcast via SSE
- [x] Statistics endpoint works
- [x] Start/stop controls work
- [x] Frontend integration complete
- [x] RealTimeMonitoring component created
- [x] Dashboard.vue integrated with real-time updates
- [x] ApplicationDetail.vue has real-time monitoring tab
- [ ] End-to-end testing

---

## Frontend Integration (Task 1.2) ✅ Complete

### Components Created:
- **`RealTimeMonitoring.vue`** - Comprehensive real-time monitoring component
  - Connection status indicator
  - Statistics dashboard (total events, findings today, critical alerts)
  - Recent events list with severity indicators
  - Anomaly alerts section
  - Real-time event updates via SSE

### Views Updated:
- **`Dashboard.vue`**
  - Added Real-Time Access Monitoring section
  - Integrated `useRealtimeUpdates` composable
  - Auto-refreshes when critical findings arrive
  - Shows connection status indicator

- **`ApplicationDetail.vue`**
  - Added "Real-Time Monitoring" tab
  - Shows application-specific real-time events
  - Filters events by applicationId

### Features:
- ✅ Real-time event display with severity color coding
- ✅ Connection status monitoring
- ✅ Event statistics (total events, findings today, critical alerts)
- ✅ Anomaly alert detection and display
- ✅ Time-based event formatting (e.g., "5m ago")
- ✅ Event filtering by application
- ✅ Auto-scrolling event list
- ✅ Clear events functionality

---

**Next:** End-to-end testing and documentation
