# Natural Language Policy Creation - Implementation Plan

**Date:** January 31, 2026  
**Status:** 📋 Planning  
**Priority:** Medium  
**Dependencies:** Phase 1-4 Complete, LLM Integration Service ✅

---

## Executive Summary

This plan outlines the implementation of natural language policy creation, enabling users to create access control policies using conversational text or voice input. This feature will dramatically lower the barrier to entry for non-technical users, allowing them to express policy requirements in plain English and have the system automatically generate structured policy definitions.

---

## Goals

1. **Text-Based Policy Creation** - Convert natural language descriptions into structured policies
2. **Voice Input Support** - Enable voice-to-text policy creation for hands-free operation
3. **Conversational Policy Builder** - Interactive chat interface for refining policy definitions
4. **Multi-Modal Input** - Support both structured forms and natural language input
5. **Confidence Scoring** - Provide confidence levels and allow user review before committing

---

## User Stories

### Story 1: Text Input Policy Creation
**As a** Data Steward (Sarah)  
**I want to** describe my access policy in plain English  
**So that** I can create policies without understanding JSON structure

**Example:**
- Input: "Allow users in the Engineering department to access resources tagged with department:engineering"
- Output: Generated ABAC policy with appropriate conditions

### Story 2: Voice Input Policy Creation
**As a** Data Owner (Michael)  
**I want to** speak my policy requirements  
**So that** I can create policies quickly while multitasking

**Example:**
- Voice: "Create a policy that denies access to customer data for contractors"
- Output: Generated policy with appropriate conditions and effect

### Story 3: Conversational Refinement
**As a** Data Steward (Sarah)  
**I want to** refine my policy through conversation  
**So that** I can ensure the policy matches my intent

**Example:**
- User: "Allow engineering to access engineering data"
- System: "I've created a policy. Should this also include read-only access for engineering managers?"
- User: "Yes, but only for data tagged with project:engineering"
- System: "Updated. Review the policy below."

---

## Technical Architecture

### 1. Natural Language Processing Pipeline

```
User Input (Text/Voice)
    ↓
[Speech-to-Text] (if voice)
    ↓
[Intent Classification]
    ↓
[Entity Extraction]
    ↓
[Policy Structure Generation]
    ↓
[Validation & Confidence Scoring]
    ↓
[User Review & Confirmation]
    ↓
[Policy Creation]
```

### 2. Core Components

#### Backend Services

**2.1 NLP Policy Generation Service**
- Location: `dashboard-api/src/policies/services/nlp-policy-generation.service.ts`
- Responsibilities:
  - Parse natural language input
  - Extract policy components (subjects, resources, conditions, effects)
  - Generate structured policy JSON
  - Calculate confidence scores
  - Handle ambiguous inputs

**2.2 Speech-to-Text Service**
- Location: `dashboard-api/src/policies/services/speech-to-text.service.ts`
- Responsibilities:
  - Convert audio input to text
  - Support multiple providers (Web Speech API, Google Cloud Speech, Azure Speech)
  - Handle real-time streaming
  - Language detection

**2.3 Policy Intent Classifier**
- Location: `dashboard-api/src/policies/services/policy-intent-classifier.service.ts`
- Responsibilities:
  - Classify user intent (create, modify, query, delete)
  - Identify policy type (RBAC vs ABAC)
  - Extract key entities (roles, departments, resources, conditions)

**2.4 Conversational Policy Builder**
- Location: `dashboard-api/src/policies/services/conversational-policy-builder.service.ts`
- Responsibilities:
  - Maintain conversation context
  - Handle follow-up questions
  - Refine policy definitions iteratively
  - Generate clarifying questions

#### Frontend Components

**2.5 Natural Language Input Component**
- Location: `dashboard-frontend/src/components/policies/NaturalLanguagePolicyInput.vue`
- Features:
  - Text input with auto-suggestions
  - Voice input button with recording indicator
  - Real-time transcription display
  - Confidence indicator
  - Policy preview panel

**2.6 Conversational Policy Builder UI**
- Location: `dashboard-frontend/src/components/policies/ConversationalPolicyBuilder.vue`
- Features:
  - Chat-like interface
  - Message history
  - Policy preview updates in real-time
  - Clarification prompts
  - Edit/refine controls

**2.7 Policy Review Component**
- Location: `dashboard-frontend/src/components/policies/PolicyReviewPanel.vue`
- Features:
  - Side-by-side comparison (natural language → structured policy)
  - Confidence breakdown
  - Edit suggestions
  - Accept/reject/modify options

---

## Implementation Phases

### Phase 1: Text-Based Policy Creation (MVP)

**Duration:** 4-6 weeks

#### Backend Tasks

1. **Extend LLM Integration Service**
   - Add policy generation prompt templates
   - Create structured output format (JSON schema)
   - Implement confidence scoring algorithm
   - Add validation against policy schema

2. **Create NLP Policy Generation Service**
   ```typescript
   @Injectable()
   export class NLPPolicyGenerationService {
     async generatePolicyFromText(
       text: string,
       context?: PolicyContext
     ): Promise<PolicyGenerationResult> {
       // Parse natural language
       // Extract entities
       // Generate policy structure
       // Validate and score
     }
   }
   ```

3. **Create Policy Intent Classifier**
   - Use LLM for intent classification
   - Extract key entities (subjects, resources, conditions)
   - Determine policy type (RBAC/ABAC)
   - Identify effect (allow/deny)

4. **API Endpoints**
   - `POST /api/policies/nlp/generate` - Generate policy from text
   - `POST /api/policies/nlp/classify-intent` - Classify user intent
   - `POST /api/policies/nlp/refine` - Refine policy through conversation

#### Frontend Tasks

1. **Natural Language Input Component**
   - Text area with placeholder examples
   - Submit button
   - Loading state
   - Error handling

2. **Policy Preview Panel**
   - Show generated policy structure
   - Display confidence score
   - Highlight uncertain parts
   - Allow editing before saving

3. **Integration with Policy Builder**
   - Add "Natural Language" tab to PolicyVisualBuilder
   - Allow switching between visual builder and NLP input
   - Sync generated policy to visual builder

#### Success Criteria
- ✅ Can generate basic RBAC policies from text
- ✅ Can generate basic ABAC policies from text
- ✅ Confidence scoring works (>70% for clear inputs)
- ✅ Generated policies pass validation
- ✅ User can review and edit before saving

---

### Phase 2: Conversational Refinement

**Duration:** 3-4 weeks

#### Backend Tasks

1. **Conversational Policy Builder Service**
   - Maintain conversation state
   - Track policy evolution
   - Generate clarifying questions
   - Handle follow-up modifications

2. **Context Management**
   - Store conversation history
   - Track policy changes during conversation
   - Maintain user preferences

3. **API Endpoints**
   - `POST /api/policies/nlp/conversation/start` - Start new conversation
   - `POST /api/policies/nlp/conversation/message` - Send message
   - `GET /api/policies/nlp/conversation/:id` - Get conversation history

#### Frontend Tasks

1. **Conversational UI Component**
   - Chat interface with message bubbles
   - Policy preview updates in real-time
   - Suggested questions/refinements
   - Conversation history

2. **Clarification Prompts**
   - Display system questions
   - Show multiple choice options
   - Allow free-form responses

#### Success Criteria
- ✅ Can refine policies through 3+ conversation turns
- ✅ System asks clarifying questions when ambiguous
- ✅ Policy updates correctly based on user responses
- ✅ Conversation history is maintained

---

### Phase 3: Voice Input Support

**Duration:** 3-4 weeks

#### Backend Tasks

1. **Speech-to-Text Service**
   - Integrate Web Speech API (browser-based)
   - Support Google Cloud Speech-to-Text API
   - Support Azure Speech Services
   - Handle real-time streaming

2. **Audio Processing**
   - Accept audio file uploads
   - Support multiple audio formats (WAV, MP3, WebM)
   - Handle noise reduction
   - Language detection

3. **API Endpoints**
   - `POST /api/policies/nlp/speech/transcribe` - Transcribe audio
   - `POST /api/policies/nlp/speech/stream` - Real-time streaming

#### Frontend Tasks

1. **Voice Input UI**
   - Record button with visual indicator
   - Real-time transcription display
   - Stop/clear controls
   - Audio playback

2. **Browser Speech API Integration**
   - Use Web Speech API for client-side transcription
   - Fallback to server-side for unsupported browsers
   - Visual feedback during recording

#### Success Criteria
- ✅ Can record voice input in browser
- ✅ Real-time transcription works
- ✅ Generated policies from voice match intent
- ✅ Works across major browsers

---

### Phase 4: Advanced Features

**Duration:** 4-5 weeks

#### Features

1. **Multi-Policy Creation**
   - Create multiple policies in one conversation
   - Batch processing
   - Policy templates from examples

2. **Policy Modification via NLP**
   - "Update policy X to also allow Y"
   - "Remove condition Z from policy Y"
   - "Change policy X effect to deny"

3. **Query Policies via NLP**
   - "What policies apply to engineering department?"
   - "Show me all policies that deny contractor access"
   - "Which policies affect customer data?"

4. **Learning from User Corrections**
   - Track user edits to generated policies
   - Improve generation accuracy over time
   - Organization-specific language patterns

5. **Multi-Language Support**
   - Support non-English input
   - Translate to policy structure
   - Localized UI

---

## Data Models

### Policy Generation Result

```typescript
interface PolicyGenerationResult {
  policy: Partial<Policy>;
  confidence: number; // 0-100
  confidenceBreakdown: {
    intent: number;
    entities: number;
    structure: number;
    validation: number;
  };
  extractedEntities: {
    subjects?: string[];
    resources?: string[];
    conditions?: string[];
    effect?: 'allow' | 'deny';
  };
  suggestions: string[];
  warnings: string[];
  alternativeInterpretations?: PolicyGenerationResult[];
}
```

### Conversation State

```typescript
interface ConversationState {
  id: string;
  userId: string;
  messages: ConversationMessage[];
  currentPolicy: Partial<Policy>;
  context: PolicyContext;
  startedAt: Date;
  lastActivity: Date;
}

interface ConversationMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  policySnapshot?: Partial<Policy>;
  confidence?: number;
}
```

---

## LLM Prompt Engineering

### Policy Generation Prompt Template

```
You are an expert security policy analyst. Convert natural language policy descriptions into structured access control policies.

Policy Types:
- RBAC (Role-Based Access Control): Policies based on user roles
- ABAC (Attribute-Based Access Control): Policies based on attributes (department, clearance, etc.)

Input: "{userInput}"

Context:
- Organization: {organizationName}
- Existing policies: {existingPolicies}
- Available roles: {availableRoles}
- Available attributes: {availableAttributes}

Generate a structured policy with:
1. Policy name (descriptive)
2. Policy type (RBAC or ABAC)
3. Effect (allow or deny)
4. Conditions/rules based on the description
5. Priority (if applicable)

Return JSON in this format:
{
  "name": "...",
  "type": "rbac" | "abac",
  "effect": "allow" | "deny",
  "description": "...",
  "conditions": [...],
  "rules": [...],
  "confidence": 0-100,
  "reasoning": "explanation of interpretation"
}
```

### Intent Classification Prompt

```
Classify the user's intent and extract key information:

Input: "{userInput}"

Classify as one of:
- create: User wants to create a new policy
- modify: User wants to modify an existing policy
- query: User wants to query existing policies
- delete: User wants to delete a policy

Extract:
- Policy type (RBAC/ABAC/unknown)
- Subjects (who)
- Resources (what)
- Conditions (when/how)
- Effect (allow/deny)

Return JSON:
{
  "intent": "...",
  "policyType": "rbac" | "abac" | "unknown",
  "subjects": [...],
  "resources": [...],
  "conditions": [...],
  "effect": "allow" | "deny" | "unknown"
}
```

---

## API Specifications

### Generate Policy from Text

**Endpoint:** `POST /api/policies/nlp/generate`

**Request:**
```json
{
  "text": "Allow users in Engineering department to access resources tagged with department:engineering",
  "context": {
    "organizationId": "org-123",
    "existingPolicies": ["policy-1", "policy-2"],
    "preferences": {
      "defaultEffect": "allow",
      "preferredType": "abac"
    }
  }
}
```

**Response:**
```json
{
  "policy": {
    "name": "Engineering Department Access",
    "type": "abac",
    "effect": "allow",
    "conditions": [
      {
        "attribute": "subject.department",
        "operator": "equals",
        "value": "Engineering"
      },
      {
        "attribute": "resource.department",
        "operator": "equals",
        "value": "engineering"
      }
    ]
  },
  "confidence": 85,
  "confidenceBreakdown": {
    "intent": 95,
    "entities": 90,
    "structure": 80,
    "validation": 75
  },
  "extractedEntities": {
    "subjects": ["Engineering department users"],
    "resources": ["resources tagged with department:engineering"],
    "effect": "allow"
  },
  "suggestions": [
    "Consider adding clearance level requirements",
    "May want to specify read vs write access"
  ],
  "warnings": [
    "Ambiguous: 'access' could mean read-only or read-write"
  ]
}
```

### Conversational Message

**Endpoint:** `POST /api/policies/nlp/conversation/message`

**Request:**
```json
{
  "conversationId": "conv-123",
  "message": "Yes, but only for read access",
  "currentPolicy": { /* policy snapshot */ }
}
```

**Response:**
```json
{
  "message": "I've updated the policy to specify read-only access. The policy now includes a condition that restricts actions to read operations.",
  "updatedPolicy": { /* updated policy */ },
  "confidence": 90,
  "questions": [
    "Should this apply to all engineering resources or only specific projects?"
  ]
}
```

---

## UI/UX Design

### Natural Language Input Interface

```
┌─────────────────────────────────────────────────┐
│ Natural Language Policy Creation                │
├─────────────────────────────────────────────────┤
│                                                  │
│  [🎤 Voice]  [📝 Text]                          │
│                                                  │
│  ┌───────────────────────────────────────────┐ │
│  │ Describe your access policy in plain      │ │
│  │ English...                                 │ │
│  │                                            │ │
│  │ Example: "Allow engineering department     │ │
│  │ users to access engineering resources"     │ │
│  └───────────────────────────────────────────┘ │
│                                                  │
│  [Generate Policy]  [Clear]                     │
│                                                  │
├─────────────────────────────────────────────────┤
│ Generated Policy Preview                        │
├─────────────────────────────────────────────────┤
│                                                  │
│  Confidence: ████████░░ 85%                     │
│                                                  │
│  Policy Name: Engineering Department Access     │
│  Type: ABAC                                     │
│  Effect: Allow                                  │
│                                                  │
│  Conditions:                                    │
│  • subject.department equals "Engineering"     │
│  • resource.department equals "engineering"    │
│                                                  │
│  [Edit] [Save Policy] [Refine with Chat]       │
│                                                  │
└─────────────────────────────────────────────────┘
```

### Conversational Builder Interface

```
┌─────────────────────────────────────────────────┐
│ Conversational Policy Builder                    │
├─────────────────────────────────────────────────┤
│                                                  │
│  🤖 System: I've created a policy based on      │
│     your description. Should this apply to       │
│     all engineering resources or only specific   │
│     projects?                                   │
│                                                  │
│  👤 You: Only for project:engineering           │
│                                                  │
│  🤖 System: Updated. The policy now includes    │
│     a condition for project:engineering.        │
│     [Policy Preview Updated]                    │
│                                                  │
│  ┌───────────────────────────────────────────┐ │
│  │ Type your message or refinement...        │ │
│  └───────────────────────────────────────────┘ │
│                                                  │
│  [Send] [🎤 Voice] [View Policy] [Save]        │
│                                                  │
└─────────────────────────────────────────────────┘
```

---

## Testing Strategy

### Unit Tests

1. **NLP Policy Generation Service**
   - Test entity extraction accuracy
   - Test policy structure generation
   - Test confidence scoring
   - Test edge cases (ambiguous input, missing information)

2. **Intent Classifier**
   - Test intent classification accuracy
   - Test entity extraction
   - Test policy type detection

3. **Conversational Builder**
   - Test conversation state management
   - Test policy refinement logic
   - Test clarifying question generation

### Integration Tests

1. **End-to-End Policy Creation**
   - Test complete flow: text → policy → save
   - Test conversational refinement flow
   - Test voice input flow

2. **LLM Integration**
   - Test with mock LLM responses
   - Test error handling
   - Test fallback behavior

### User Acceptance Tests

1. **Non-Technical User Testing**
   - Can create policies without technical knowledge
   - Generated policies match user intent
   - Confidence scores are accurate

2. **Voice Input Testing**
   - Voice transcription accuracy
   - Real-time transcription works
   - Works across browsers

---

## Performance Requirements

- **Text Processing:** < 2 seconds for policy generation
- **Voice Transcription:** < 5 seconds for 30-second audio
- **Conversational Response:** < 3 seconds for refinement
- **Confidence Calculation:** < 500ms

---

## Security Considerations

1. **Input Validation**
   - Sanitize user input
   - Validate generated policies before saving
   - Prevent injection attacks

2. **LLM Security**
   - Don't expose sensitive data in prompts
   - Rate limiting on LLM calls
   - Audit LLM interactions

3. **Voice Data**
   - Encrypt audio in transit
   - Don't store audio files long-term
   - Comply with privacy regulations

---

## Future Enhancements

1. **Policy Templates from Examples**
   - Learn from user corrections
   - Build organization-specific templates
   - Improve accuracy over time

2. **Multi-Language Support**
   - Support non-English input
   - Localized policy generation

3. **Visual Policy Editing**
   - Allow editing generated policies visually
   - Sync changes back to natural language

4. **Policy Explanation**
   - Explain existing policies in natural language
   - Answer questions about policies

5. **Batch Policy Creation**
   - Create multiple policies from one description
   - Policy sets and templates

---

## Success Metrics

- **Adoption:** 50% of new policies created via NLP within 6 months
- **Accuracy:** 85%+ of generated policies match user intent without edits
- **Time Savings:** 60% reduction in time to create policies
- **User Satisfaction:** 4.5+ star rating from non-technical users
- **Confidence Score Accuracy:** Generated confidence scores correlate with user acceptance (>80% correlation)

---

## Dependencies

- ✅ LLM Integration Service (exists)
- ✅ Policy Builder (Phase 1-4)
- ✅ Policy Validation Service
- ⚠️ Speech-to-Text API (needs integration)
- ⚠️ Conversation State Storage (needs implementation)

---

## Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| LLM generates incorrect policies | High | Medium | Always require user review, validate against schema, provide confidence scores |
| Ambiguous user input | Medium | High | Ask clarifying questions, show alternative interpretations |
| Voice transcription errors | Medium | Medium | Allow text editing after transcription, show confidence |
| Performance issues with LLM | Medium | Low | Cache common patterns, use async processing, show progress |
| Cost of LLM API calls | Low | Medium | Rate limiting, caching, batch processing |

---

**Document End**

*This plan will be updated as implementation progresses and requirements evolve.*
