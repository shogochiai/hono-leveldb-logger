import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuthService } from '../../../src/auth/services/auth-service';
import { LevelDBAdapter } from '../../../src/storage/leveldb-adapter';
import { AuthConfig, AuthMethod } from '../../../src/auth/types';
import { AuthUtils } from '../../../src/auth/utils/auth-utils';
import crypto from 'crypto';

describe('AuthService', () => {
  let authService: AuthService;
  let storage: LevelDBAdapter;
  let authConfig: AuthConfig;

  beforeEach(async () => {
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

    // 一意のテストキーとパスを生成
    const testKey = crypto.randomBytes(32).toString('hex');
    const testDbPath = `/tmp/test-db-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    storage = new LevelDBAdapter(testKey, testDbPath);
    await storage.initialize(['tokyo-dc1']);
    authService = new AuthService(storage, authConfig);
  });

  afterEach(async () => {
    // クリーンアップ
    if (storage) {
      await storage.close();
    }
  });

  describe('Service Registration', () => {
    it('should register a new service', async () => {
      const registration = {
        serviceId: 'test-service',
        serviceName: 'Test Service',
        permissions: ['logs:read', 'logs:write'],
        isActive: true
      };

      const credentials = await authService.registerService(registration);

      expect(credentials).toBeDefined();
      expect(credentials.serviceId).toBe('test-service');
      expect(credentials.serviceName).toBe('Test Service');
      expect(credentials.permissions).toEqual(['logs:read', 'logs:write']);
      expect(credentials.apiKey).toBeDefined();
      expect(credentials.publicKey).toBeDefined();
      expect(credentials.privateKey).toBeDefined();
    });

    it('should rotate service credentials', async () => {
      // まずサービスを登録
      const registration = {
        serviceId: 'test-service',
        serviceName: 'Test Service',
        permissions: ['logs:read'],
        isActive: true
      };

      const originalCredentials = await authService.registerService(registration);
      
      // 認証情報をローテーション
      const newCredentials = await authService.rotateServiceCredentials('test-service');

      expect(newCredentials.serviceId).toBe(originalCredentials.serviceId);
      expect(newCredentials.serviceName).toBe(originalCredentials.serviceName);
      expect(newCredentials.apiKey).not.toBe(originalCredentials.apiKey);
      expect(newCredentials.publicKey).not.toBe(originalCredentials.publicKey);
      expect(newCredentials.privateKey).not.toBe(originalCredentials.privateKey);
    });
  });

  describe('JWT Authentication', () => {
    it('should authenticate valid JWT token', async () => {
      // サービスを登録
      const registration = {
        serviceId: 'jwt-test-service',
        serviceName: 'JWT Test Service',
        permissions: ['logs:read', 'logs:write'],
        isActive: true
      };

      await authService.registerService(registration);

      // JWT トークンを生成
      const payload = {
        sub: 'jwt-test-service',
        permissions: ['logs:read', 'logs:write']
      };

      const token = AuthUtils.generateJWT(payload, authConfig);

      // 認証を実行
      const result = await authService.authenticateJWT(token);

      expect(result.success).toBe(true);
      expect(result.serviceId).toBe('jwt-test-service');
      expect(result.serviceName).toBe('JWT Test Service');
      expect(result.permissions).toEqual(['logs:read', 'logs:write']);
      expect(result.method).toBe(AuthMethod.JWT);
    });

    it('should reject invalid JWT token', async () => {
      const invalidToken = 'invalid.jwt.token';

      const result = await authService.authenticateJWT(invalidToken);

      expect(result.success).toBe(false);
      expect(result.error).toContain('JWT verification failed');
      expect(result.method).toBe(AuthMethod.JWT);
    });

    it('should reject JWT for inactive service', async () => {
      // 非アクティブなサービスを登録
      const registration = {
        serviceId: 'inactive-service',
        serviceName: 'Inactive Service',
        permissions: ['logs:read'],
        isActive: false
      };

      await authService.registerService(registration);

      const payload = {
        sub: 'inactive-service',
        permissions: ['logs:read']
      };

      const token = AuthUtils.generateJWT(payload, authConfig);
      const result = await authService.authenticateJWT(token);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Service not found or inactive');
    });
  });

  describe('API Key Authentication', () => {
    it('should authenticate valid API key', async () => {
      // サービスを登録
      const registration = {
        serviceId: 'api-test-service',
        serviceName: 'API Test Service',
        permissions: ['logs:write'],
        isActive: true
      };

      const credentials = await authService.registerService(registration);

      // API Key 認証情報を生成
      const timestamp = Date.now();
      const nonce = AuthUtils.generateNonce();
      const method = 'POST';
      const path = '/api/logs';
      const body = JSON.stringify({ test: 'data' });

      const signature = AuthUtils.generateApiKeySignature(
        credentials.apiKey!,
        timestamp,
        nonce,
        authConfig.apiKeySecret,
        method,
        path,
        body
      );

      const auth = {
        apiKey: credentials.apiKey!,
        signature,
        timestamp,
        nonce
      };

      // 認証を実行
      const result = await authService.authenticateApiKey(auth, method, path, body);

      expect(result.success).toBe(true);
      expect(result.serviceId).toBe('api-test-service');
      expect(result.serviceName).toBe('API Test Service');
      expect(result.permissions).toEqual(['logs:write']);
      expect(result.method).toBe(AuthMethod.API_KEY);
    });

    it('should reject API key with invalid signature', async () => {
      const registration = {
        serviceId: 'api-test-service-2',
        serviceName: 'API Test Service 2',
        permissions: ['logs:write'],
        isActive: true
      };

      const credentials = await authService.registerService(registration);

      const auth = {
        apiKey: credentials.apiKey!,
        signature: 'invalid-signature',
        timestamp: Date.now(),
        nonce: AuthUtils.generateNonce()
      };

      const result = await authService.authenticateApiKey(auth, 'POST', '/api/logs');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid signature');
      expect(result.method).toBe(AuthMethod.API_KEY);
    });

    it('should reject API key with expired timestamp', async () => {
      const registration = {
        serviceId: 'api-test-service-3',
        serviceName: 'API Test Service 3',
        permissions: ['logs:write'],
        isActive: true
      };

      const credentials = await authService.registerService(registration);

      const expiredTimestamp = Date.now() - 600000; // 10 minutes ago
      const nonce = AuthUtils.generateNonce();

      const signature = AuthUtils.generateApiKeySignature(
        credentials.apiKey!,
        expiredTimestamp,
        nonce,
        authConfig.apiKeySecret,
        'POST',
        '/api/logs'
      );

      const auth = {
        apiKey: credentials.apiKey!,
        signature,
        timestamp: expiredTimestamp,
        nonce
      };

      const result = await authService.authenticateApiKey(auth, 'POST', '/api/logs');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid timestamp');
      expect(result.method).toBe(AuthMethod.API_KEY);
    });
  });

  describe('mTLS Authentication', () => {
    it('should authenticate valid client certificate', async () => {
      // サービスを登録
      const registration = {
        serviceId: 'mtls-test-service',
        serviceName: 'mTLS Test Service',
        permissions: ['logs:read', 'logs:write'],
        isActive: true
      };

      await authService.registerService(registration);

      // 模擬クライアント証明書
      const clientCert = 'CN=mtls-test-service,O=Test Organization';

      const result = await authService.authenticateMTLS(clientCert);

      expect(result.success).toBe(true);
      expect(result.serviceId).toBe('mtls-test-service');
      expect(result.serviceName).toBe('mTLS Test Service');
      expect(result.permissions).toEqual(['logs:read', 'logs:write']);
      expect(result.method).toBe(AuthMethod.MTLS);
    });

    it('should reject certificate for unknown service', async () => {
      const clientCert = 'CN=unknown-service,O=Test Organization';

      const result = await authService.authenticateMTLS(clientCert);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Service not found or inactive');
      expect(result.method).toBe(AuthMethod.MTLS);
    });

    it('should reject invalid certificate format', async () => {
      const invalidCert = 'invalid-certificate-format';

      const result = await authService.authenticateMTLS(invalidCert);

      expect(result.success).toBe(false);
      expect(result.error).toContain('mTLS authentication failed');
      expect(result.method).toBe(AuthMethod.MTLS);
    });
  });
});

