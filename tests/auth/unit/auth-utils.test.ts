import { describe, it, expect, beforeEach } from 'vitest';
import { AuthUtils } from '../../../src/auth/utils/auth-utils';
import { AuthConfig } from '../../../src/auth/types';

describe('AuthUtils', () => {
  let authConfig: AuthConfig;

  beforeEach(() => {
    authConfig = {
      jwtSecret: 'test-secret-key',
      jwtIssuer: 'test-issuer',
      jwtAudience: 'test-audience',
      jwtExpirationTime: '1h',
      apiKeySecret: 'test-api-secret',
      nonceWindowMs: 300000,
      cacheExpirationMs: 300000,
      rateLimitPerMinute: 1000,
      enableMTLS: false
    };
  });

  describe('JWT Operations', () => {
    it('should generate and verify JWT token', () => {
      const payload = {
        sub: 'test-service',
        permissions: ['logs:read', 'logs:write']
      };

      const token = AuthUtils.generateJWT(payload, authConfig);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      const decoded = AuthUtils.verifyJWT(token, authConfig);
      expect(decoded.sub).toBe('test-service');
      expect(decoded.permissions).toEqual(['logs:read', 'logs:write']);
      expect(decoded.iss).toBe('test-issuer');
      expect(decoded.aud).toBe('test-audience');
    });

    it('should fail to verify invalid JWT token', () => {
      const invalidToken = 'invalid.jwt.token';
      
      expect(() => {
        AuthUtils.verifyJWT(invalidToken, authConfig);
      }).toThrow('JWT verification failed');
    });

    it('should fail to verify JWT with wrong secret', () => {
      const payload = {
        sub: 'test-service',
        permissions: ['logs:read']
      };

      const token = AuthUtils.generateJWT(payload, authConfig);
      
      const wrongConfig = { ...authConfig, jwtSecret: 'wrong-secret' };
      
      expect(() => {
        AuthUtils.verifyJWT(token, wrongConfig);
      }).toThrow('JWT verification failed');
    });
  });

  describe('API Key Signature', () => {
    it('should generate and verify API key signature', () => {
      const apiKey = 'test-api-key';
      const timestamp = Date.now();
      const nonce = AuthUtils.generateNonce();
      const method = 'POST';
      const path = '/api/logs';
      const body = JSON.stringify({ test: 'data' });

      const signature = AuthUtils.generateApiKeySignature(
        apiKey,
        timestamp,
        nonce,
        authConfig.apiKeySecret,
        method,
        path,
        body
      );

      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');

      const isValid = AuthUtils.verifyApiKeySignature(
        { apiKey, signature, timestamp, nonce },
        authConfig.apiKeySecret,
        method,
        path,
        body
      );

      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong signature', () => {
      const apiKey = 'test-api-key';
      const timestamp = Date.now();
      const nonce = AuthUtils.generateNonce();

      const isValid = AuthUtils.verifyApiKeySignature(
        { apiKey, signature: 'wrong-signature', timestamp, nonce },
        authConfig.apiKeySecret,
        'POST',
        '/api/logs'
      );

      expect(isValid).toBe(false);
    });

    it('should fail verification with modified body', () => {
      const apiKey = 'test-api-key';
      const timestamp = Date.now();
      const nonce = AuthUtils.generateNonce();
      const method = 'POST';
      const path = '/api/logs';
      const originalBody = JSON.stringify({ test: 'data' });
      const modifiedBody = JSON.stringify({ test: 'modified' });

      const signature = AuthUtils.generateApiKeySignature(
        apiKey,
        timestamp,
        nonce,
        authConfig.apiKeySecret,
        method,
        path,
        originalBody
      );

      const isValid = AuthUtils.verifyApiKeySignature(
        { apiKey, signature, timestamp, nonce },
        authConfig.apiKeySecret,
        method,
        path,
        modifiedBody
      );

      expect(isValid).toBe(false);
    });
  });

  describe('Utility Functions', () => {
    it('should generate unique nonces', () => {
      const nonce1 = AuthUtils.generateNonce();
      const nonce2 = AuthUtils.generateNonce();

      expect(nonce1).toBeDefined();
      expect(nonce2).toBeDefined();
      expect(nonce1).not.toBe(nonce2);
      expect(nonce1.length).toBe(32); // 16 bytes = 32 hex chars
    });

    it('should validate timestamps correctly', () => {
      const now = Date.now();
      const validTimestamp = now - 60000; // 1 minute ago
      const invalidTimestamp = now - 600000; // 10 minutes ago

      expect(AuthUtils.isTimestampValid(validTimestamp, 300000)).toBe(true);
      expect(AuthUtils.isTimestampValid(invalidTimestamp, 300000)).toBe(false);
    });

    it('should check permissions correctly', () => {
      const userPermissions = ['logs:read', 'logs:write', 'admin:users'];

      // Exact match
      expect(AuthUtils.hasPermission(userPermissions, ['logs:read'])).toBe(true);
      expect(AuthUtils.hasPermission(userPermissions, ['logs:delete'])).toBe(false);

      // Multiple permissions
      expect(AuthUtils.hasPermission(userPermissions, ['logs:read', 'logs:write'])).toBe(true);
      expect(AuthUtils.hasPermission(userPermissions, ['logs:read', 'logs:delete'])).toBe(false);

      // Wildcard permissions
      const wildcardPermissions = ['logs:*'];
      expect(AuthUtils.hasPermission(wildcardPermissions, ['logs:read'])).toBe(true);
      expect(AuthUtils.hasPermission(wildcardPermissions, ['logs:write'])).toBe(true);
      expect(AuthUtils.hasPermission(wildcardPermissions, ['admin:users'])).toBe(false);

      // Super admin
      const superAdminPermissions = ['*'];
      expect(AuthUtils.hasPermission(superAdminPermissions, ['logs:read'])).toBe(true);
      expect(AuthUtils.hasPermission(superAdminPermissions, ['admin:users'])).toBe(true);
    });

    it('should generate RSA key pairs', () => {
      const { publicKey, privateKey } = AuthUtils.generateKeyPair();

      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      expect(publicKey.includes('BEGIN PUBLIC KEY')).toBe(true);
      expect(privateKey.includes('BEGIN PRIVATE KEY')).toBe(true);
    });

    it('should sign and verify RSA signatures', () => {
      const { publicKey, privateKey } = AuthUtils.generateKeyPair();
      const data = 'test data to sign';

      const signature = AuthUtils.signWithRSA(data, privateKey);
      expect(signature).toBeDefined();

      const isValid = AuthUtils.verifyRSASignature(data, signature, publicKey);
      expect(isValid).toBe(true);

      // Test with modified data
      const isInvalid = AuthUtils.verifyRSASignature('modified data', signature, publicKey);
      expect(isInvalid).toBe(false);
    });

    it('should generate secure random strings', () => {
      const random1 = AuthUtils.generateSecureRandom(16);
      const random2 = AuthUtils.generateSecureRandom(16);

      expect(random1).toBeDefined();
      expect(random2).toBeDefined();
      expect(random1).not.toBe(random2);
      expect(random1.length).toBe(32); // 16 bytes = 32 hex chars
    });

    it('should hash data correctly', () => {
      const data = 'test data';
      const hash1 = AuthUtils.hash(data);
      const hash2 = AuthUtils.hash(data);

      expect(hash1).toBeDefined();
      expect(hash1).toBe(hash2); // Same input should produce same hash
      expect(hash1.length).toBe(64); // SHA256 = 64 hex chars
    });
  });
});

