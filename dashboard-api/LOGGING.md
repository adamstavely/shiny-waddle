# Logging Configuration

The dashboard API uses a structured logging system with environment-based log level control and JSON formatting for production.

## Log Levels

The logging system supports the following log levels (in order of severity):

- **VERBOSE** (0) - Very detailed information, typically only useful for debugging
- **DEBUG** (1) - Detailed information for debugging
- **INFO** (2) - General informational messages
- **WARN** (3) - Warning messages for potentially harmful situations
- **ERROR** (4) - Error messages for error events

## Environment Configuration

### Log Level

Set the log level using the `LOG_LEVEL` environment variable:

```bash
# Development - show debug and above
LOG_LEVEL=DEBUG

# Production - show warnings and errors only
LOG_LEVEL=WARN

# Test - show errors only
LOG_LEVEL=ERROR
```

**Default behavior:**
- **Production**: `WARN` (warnings and errors only)
- **Development**: `DEBUG` (debug, info, warnings, and errors)
- **Test**: `ERROR` (errors only)

### Log Format

Set the log format using the `LOG_FORMAT` environment variable:

```bash
# JSON format (default in production)
LOG_FORMAT=json

# Human-readable format (default in development)
LOG_FORMAT=pretty
```

**Default behavior:**
- **Production**: JSON format (for log aggregation tools)
- **Development**: Human-readable format

## Usage in Services

### Basic Usage

```typescript
import { AppLogger } from '../common/services/logger.service';

@Injectable()
export class MyService {
  private readonly logger = new AppLogger(MyService.name);

  someMethod() {
    this.logger.log('Informational message');
    this.logger.debug('Debug information');
    this.logger.warn('Warning message');
    this.logger.error('Error message', error.stack, { metadata: 'value' });
  }
}
```

### Log Methods

- `log(message, context?, metadata?)` - Log informational message
- `debug(message, context?, metadata?)` - Log debug message
- `warn(message, context?, metadata?)` - Log warning message
- `error(message, trace?, context?, metadata?)` - Log error message with optional stack trace
- `verbose(message, context?, metadata?)` - Log verbose message

### Metadata

You can include structured metadata with log messages:

```typescript
this.logger.error(
  'Failed to process request',
  error.stack,
  { requestId: '123', userId: 'user-456' }
);
```

## Log Output Formats

### JSON Format (Production)

```json
{
  "timestamp": "2026-01-24T12:34:56.789Z",
  "level": "ERROR",
  "context": "MyService",
  "message": "Failed to process request",
  "trace": "Error: ...\n    at ...",
  "metadata": {
    "requestId": "123",
    "userId": "user-456"
  }
}
```

### Human-Readable Format (Development)

```
[ERROR] [MyService] Failed to process request
Error: ...
    at ...
Metadata: {
  "requestId": "123",
  "userId": "user-456"
}
```

## Examples

### Environment Variables

```bash
# Production configuration
NODE_ENV=production
LOG_LEVEL=WARN
LOG_FORMAT=json

# Development configuration
NODE_ENV=development
LOG_LEVEL=DEBUG
LOG_FORMAT=pretty

# Test configuration
NODE_ENV=test
LOG_LEVEL=ERROR
LOG_FORMAT=json
```

### Docker Compose

```yaml
services:
  api:
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=WARN
      - LOG_FORMAT=json
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-config
data:
  LOG_LEVEL: "WARN"
  LOG_FORMAT: "json"
```

## Integration with Log Aggregation Tools

The JSON format is designed to work seamlessly with log aggregation tools:

- **Elasticsearch/ELK Stack**: Direct JSON ingestion
- **Datadog**: JSON parsing for structured logs
- **Splunk**: JSON field extraction
- **CloudWatch Logs**: JSON log groups
- **GCP Cloud Logging**: Structured JSON logs

## Best Practices

1. **Use appropriate log levels**: Don't log everything at ERROR level
2. **Include context**: Always include relevant context in metadata
3. **Don't log sensitive data**: Never log passwords, tokens, or PII
4. **Use structured metadata**: Prefer metadata objects over string concatenation
5. **Error logging**: Always include stack traces for errors
6. **Performance**: Logging is asynchronous and won't block requests

## Migration from console.log

If you're migrating from `console.log` statements:

```typescript
// Before
console.log('Processing request');
console.error('Error:', error);

// After
this.logger.log('Processing request');
this.logger.error('Error', error instanceof Error ? error.stack : String(error));
```
