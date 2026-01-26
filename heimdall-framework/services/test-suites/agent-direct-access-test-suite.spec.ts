/**
 * Agent Direct Access Test Suite Unit Tests
 */

import { AgentDirectAccessTestSuite } from './agent-direct-access-test-suite';
import { AccessControlConfig, OAuthFlowConfig } from '../../core/types';
import { AgentAccessControlTester } from '../agent-access-control-tester';
import { AgentOAuthTester } from '../agent-oauth-tester';

// Mock dependencies
jest.mock('../agent-access-control-tester');
jest.mock('../agent-oauth-tester');

describe('AgentDirectAccessTestSuite', () => {
  let suite: AgentDirectAccessTestSuite;
  let mockAccessControlTester: jest.Mocked<AgentAccessControlTester>;
  let mockOAuthTester: jest.Mocked<AgentOAuthTester>;
  let config: AccessControlConfig;

  beforeEach(() => {
    config = {
      policyEngine: 'custom',
      cacheDecisions: true,
      policyMode: 'hybrid',
    };

    mockAccessControlTester = {
      testDirectAccess: jest.fn(),
    } as any;

    mockOAuthTester = {
      testClientCredentialsFlow: jest.fn(),
    } as any;

    (AgentAccessControlTester as any).mockImplementation(() => mockAccessControlTester);
    (AgentOAuthTester as any).mockImplementation(() => mockOAuthTester);

    const oauthConfig: OAuthFlowConfig = {
      tokenEndpoint: 'https://auth.example.com/token',
      clientId: 'test-client',
      clientSecret: 'test-secret',
      scopes: ['read:logs'],
    };

    suite = new AgentDirectAccessTestSuite({
      accessControlConfig: config,
      oauthConfig,
    });
  });

  describe('testAutonomousOperation', () => {
    it('should test autonomous operation', async () => {
      mockAccessControlTester.testDirectAccess.mockResolvedValue({
        testType: 'agent-direct-access',
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        testType: 'direct',
        agentId: 'agent-002',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
      });

      const result = await suite.testAutonomousOperation(
        'agent-002',
        'autonomous',
        {
          id: 'logs-123',
          type: 'logs',
          attributes: {},
        },
        'read',
        true
      );

      expect(result.passed).toBe(true);
      expect(result.testType).toBe('agent-direct-access');
    });
  });

  describe('testServiceToServiceAuth', () => {
    it('should test service-to-service authentication', async () => {
      mockOAuthTester.testClientCredentialsFlow.mockResolvedValue({
        testType: 'agent-direct-access',
        testName: 'Client Credentials Flow Test',
        passed: true,
        timestamp: new Date(),
        flowType: 'client-credentials',
        tokenIssued: true,
        tokenValid: true,
        scopesGranted: ['read:logs'],
        scopesExpected: ['read:logs'],
        credentialSecurity: true,
      });

      const result = await suite.testServiceToServiceAuth('agent-002', ['read:logs']);

      expect(result.passed).toBe(true);
      expect(result.details?.tokenIssued).toBe(true);
    });

    it('should return error when OAuth config is missing', async () => {
      const suiteWithoutOAuth = new AgentDirectAccessTestSuite({
        accessControlConfig: config,
      });

      const result = await suiteWithoutOAuth.testServiceToServiceAuth('agent-002', ['read:logs']);

      expect(result.passed).toBe(false);
      expect(result.error).toContain('OAuth configuration not provided');
    });
  });

  describe('testEventTriggeredAction', () => {
    it('should test event-triggered action', async () => {
      mockAccessControlTester.testDirectAccess.mockResolvedValue({
        testType: 'agent-direct-access',
        testName: 'Test',
        passed: true,
        timestamp: new Date(),
        testType: 'direct',
        agentId: 'agent-002',
        allowed: true,
        expectedAllowed: true,
        decisionReason: 'Allowed',
      });

      const result = await suite.testEventTriggeredAction(
        'agent-002',
        'security-incident',
        {
          id: 'incident-123',
          type: 'incidents',
          attributes: {},
        },
        'write',
        {
          ipAddress: '192.168.1.100',
          timeOfDay: '14:30',
        }
      );

      expect(result.passed).toBe(true);
      expect(result.details?.eventType).toBe('security-incident');
    });
  });

  describe('testCredentialRotation', () => {
    it('should test credential rotation', async () => {
      mockOAuthTester.testClientCredentialsFlow
        .mockResolvedValueOnce({
          testType: 'agent-direct-access',
          testName: 'Client Credentials Flow Test',
          passed: true,
          timestamp: new Date(),
          flowType: 'client-credentials',
          tokenIssued: true,
          tokenValid: true,
          scopesGranted: ['read:logs'],
          scopesExpected: ['read:logs'],
          credentialSecurity: true, // Rotation enabled
        })
        .mockResolvedValueOnce({
          testType: 'agent-direct-access',
          testName: 'Client Credentials Flow Test',
          passed: true,
          timestamp: new Date(),
          flowType: 'client-credentials',
          tokenIssued: true,
          tokenValid: true,
          scopesGranted: ['read:logs'],
          scopesExpected: ['read:logs'],
          credentialSecurity: false, // Rotation disabled
        });

      const result = await suite.testCredentialRotation('agent-002', ['read:logs']);

      expect(result.passed).toBe(true);
      expect(result.details?.rotationEnabled).toBe(true);
      expect(result.details?.rotationDisabled).toBe(false);
    });
  });
});
