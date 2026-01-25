# Elasticsearch Integration for Real-Time Monitoring

## Overview

Real-time monitoring events are automatically sent to Elasticsearch for dashboarding, reporting, and historical analysis. This integration uses the Elastic Common Schema (ECS) format for seamless compatibility with Elasticsearch, Kibana, and other ECS-compatible tools.

## Features

- ✅ **Automatic Indexing**: All real-time findings are automatically indexed to Elasticsearch
- ✅ **ECS Format**: Findings are converted to Elastic Common Schema format
- ✅ **Date-based Indices**: Automatic index rotation using date patterns
- ✅ **Bulk Operations**: Efficient bulk indexing for multiple findings
- ✅ **Error Handling**: Graceful degradation if Elasticsearch is unavailable
- ✅ **Configurable**: Environment variable-based configuration

## Installation

### 1. Install Elasticsearch Client

```bash
cd dashboard-api
npm install @elastic/elasticsearch
```

### 2. Configure Environment Variables

Add the following to your `.env` file:

```bash
# Enable Elasticsearch integration
ELASTICSEARCH_ENABLED=true

# Elasticsearch connection (choose one)
# Option 1: Self-hosted Elasticsearch
ELASTICSEARCH_NODE=http://localhost:9200
# Or multiple nodes:
ELASTICSEARCH_NODE=http://node1:9200,http://node2:9200

# Option 2: Elastic Cloud
ELASTICSEARCH_CLOUD_ID=your-cloud-id

# Authentication (choose one)
# Username/Password
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your-password

# Or API Key
ELASTICSEARCH_API_KEY=your-api-key

# Optional: Custom index prefix (default: heimdall-realtime)
ELASTICSEARCH_INDEX_PREFIX=heimdall-realtime

# Optional: Connection settings
ELASTICSEARCH_MAX_RETRIES=3
ELASTICSEARCH_REQUEST_TIMEOUT=30000
```

## Index Structure

### Findings Index

**Index Pattern**: `heimdall-realtime-findings-YYYY.MM.DD`

**Example**: `heimdall-realtime-findings-2025.01.25`

**Document Format**: ECS-compatible documents with Heimdall custom fields

### Events Index

**Index Pattern**: `heimdall-realtime-events-YYYY.MM.DD`

**Example**: `heimdall-realtime-events-2025.01.25`

**Document Format**: ECS event documents for real-time monitoring events

## ECS Document Structure

All findings are converted to ECS format using the `ECSAdapter`. Key fields include:

### Standard ECS Fields

- `@timestamp` - ISO 8601 timestamp
- `event.kind` - Always "event"
- `event.category` - Security category
- `event.type` - Finding type
- `event.action` - Action (detected, normalized, scored)
- `event.severity` - Numeric severity (1=critical, 5=info)
- `message` - Finding title/description

### Heimdall Custom Fields

All custom fields are prefixed with `heimdall.*`:

- `heimdall.finding.id` - Unique finding ID
- `heimdall.scanner.source` - Scanner source type
- `heimdall.scanner.id` - Scanner identifier
- `heimdall.scanner.finding_id` - Original scanner finding ID
- `heimdall.asset.type` - Asset type (application, database, etc.)
- `heimdall.asset.application_id` - Application ID
- `heimdall.asset.component` - Component name
- `heimdall.status` - Finding status
- `heimdall.risk_score` - Risk score (0-100)
- `heimdall.business_impact` - Business impact assessment

### Vulnerability Fields (if applicable)

- `vulnerability.id` - CVE/CWE ID
- `vulnerability.cve.id` - CVE identifier
- `vulnerability.cve.description` - CVE description
- `vulnerability.cve.score.base` - CVSS base score
- `vulnerability.severity` - Severity level

## API Endpoints

### Test Connection

```http
GET /api/v1/elasticsearch/test
```

**Response:**
```json
{
  "enabled": true,
  "connected": true,
  "message": "Successfully connected to Elasticsearch"
}
```

### Get Cluster Info

```http
GET /api/v1/elasticsearch/info
```

**Response:**
```json
{
  "enabled": true,
  "info": {
    "name": "elasticsearch-node",
    "cluster_name": "elasticsearch",
    "version": {
      "number": "8.11.0"
    }
  }
}
```

### Manual Index Finding (for testing)

```http
POST /api/v1/elasticsearch/index-finding
Content-Type: application/json

{
  "id": "finding-123",
  "title": "Test Finding",
  "severity": "high",
  ...
}
```

## Kibana Dashboard Setup

### 1. Create Index Pattern

1. Open Kibana → Stack Management → Index Patterns
2. Create index pattern: `heimdall-realtime-findings-*`
3. Select `@timestamp` as the time field
4. Create another pattern: `heimdall-realtime-events-*`

### 2. Sample Visualizations

#### Findings by Severity

```
Visualization Type: Pie Chart
Index Pattern: heimdall-realtime-findings-*
Aggregation: Terms
Field: event.severity
```

#### Findings Over Time

```
Visualization Type: Line Chart
Index Pattern: heimdall-realtime-findings-*
X-Axis: Date Histogram (@timestamp)
Y-Axis: Count
```

#### Top Applications by Findings

```
Visualization Type: Horizontal Bar
Index Pattern: heimdall-realtime-findings-*
Aggregation: Terms
Field: heimdall.asset.application_id
Size: 10
```

#### Risk Score Distribution

```
Visualization Type: Histogram
Index Pattern: heimdall-realtime-findings-*
Field: heimdall.risk_score
Interval: 10
```

### 3. Create Dashboard

1. Open Kibana → Dashboard → Create Dashboard
2. Add visualizations created above
3. Add filters for:
   - `heimdall.asset.application_id`
   - `event.severity`
   - `heimdall.status`
   - Time range

## Integration Points

### RealtimeService Integration

The `RealtimeService` automatically sends events to Elasticsearch:

1. **Finding Normalized**: When a finding is normalized, it's indexed to `heimdall-realtime-findings-*`
2. **Finding Scored**: When risk scoring completes, the finding is re-indexed with updated risk score
3. **Scoring Event**: A separate event is indexed to `heimdall-realtime-events-*`
4. **Error Events**: Ingestion errors are indexed as events

### Event Flow

```
Webhook → RealtimeIngestionService
         ↓
    Normalize Finding
         ↓
    Store in UnifiedFindingsService
         ↓
    Index to Elasticsearch ← NEW
         ↓
    Broadcast via SSE
```

## Error Handling

- **Graceful Degradation**: If Elasticsearch is unavailable, real-time ingestion continues
- **Non-blocking**: Elasticsearch failures don't break the ingestion pipeline
- **Retry Logic**: Built-in retry mechanism (configurable via `ELASTICSEARCH_MAX_RETRIES`)
- **Logging**: All errors are logged but don't throw exceptions

## Performance Considerations

### Bulk Indexing

For high-volume scenarios, findings are indexed individually. For batch operations, consider using `bulkIndexFindings()`:

```typescript
await elasticsearchService.bulkIndexFindings(findings);
```

### Index Management

- **Date-based indices**: Automatically rotate daily
- **Index Lifecycle Management (ILM)**: Configure ILM policies in Elasticsearch to:
  - Roll over indices when they reach a certain size
  - Delete old indices after retention period
  - Optimize indices for better performance

### Recommended ILM Policy

```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "7d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

## Monitoring

### Health Check

Monitor Elasticsearch connection health:

```bash
curl http://localhost:3001/api/v1/elasticsearch/test
```

### Metrics to Monitor

- **Indexing Rate**: Documents indexed per second
- **Indexing Errors**: Failed indexing operations
- **Index Size**: Size of indices over time
- **Query Performance**: Kibana dashboard load times

## Troubleshooting

### Elasticsearch Not Indexing

1. **Check if enabled**:
   ```bash
   curl http://localhost:3001/api/v1/elasticsearch/test
   ```

2. **Check logs**:
   ```bash
   # Look for Elasticsearch errors in application logs
   grep -i elasticsearch logs/app.log
   ```

3. **Verify connection**:
   ```bash
   # Test Elasticsearch directly
   curl http://localhost:9200
   ```

### Common Issues

**Issue**: "Elasticsearch client not available"
- **Solution**: Install `@elastic/elasticsearch`: `npm install @elastic/elasticsearch`

**Issue**: "Connection refused"
- **Solution**: Check `ELASTICSEARCH_NODE` environment variable and ensure Elasticsearch is running

**Issue**: "Authentication failed"
- **Solution**: Verify `ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD` or `ELASTICSEARCH_API_KEY`

**Issue**: "Index not found"
- **Solution**: Indices are created automatically on first document. Ensure Elasticsearch has proper permissions.

## Files Created

- `dashboard-api/src/elasticsearch/elasticsearch.service.ts` - Core Elasticsearch service
- `dashboard-api/src/elasticsearch/elasticsearch.module.ts` - NestJS module
- `dashboard-api/src/elasticsearch/elasticsearch.controller.ts` - API endpoints

## Files Modified

- `dashboard-api/src/realtime/realtime.service.ts` - Integrated Elasticsearch indexing
- `dashboard-api/src/realtime/realtime.module.ts` - Added ElasticsearchModule import
- `dashboard-api/src/app.module.ts` - Added ElasticsearchModule
- `dashboard-api/package.json` - Added @elastic/elasticsearch dependency

## Next Steps

1. **Install Elasticsearch client**: `npm install @elastic/elasticsearch`
2. **Configure environment variables**: Set `ELASTICSEARCH_ENABLED=true` and connection details
3. **Test connection**: Use `/api/v1/elasticsearch/test` endpoint
4. **Create Kibana dashboards**: Set up index patterns and visualizations
5. **Configure ILM policies**: Set up index lifecycle management for retention

---

**Status**: ✅ Complete - Ready for use after installing @elastic/elasticsearch
