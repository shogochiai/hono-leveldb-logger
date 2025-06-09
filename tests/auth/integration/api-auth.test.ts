import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LevelDBAdapter } from '../../../src/storage/leveldb-adapter';
import { createApp } from '../../../src/api/routes';
import { AuthConfig } from '../../../src/auth/types';
import { AuthUtils } from '../../../src/auth/utils/auth-utils';
import crypto from 'crypto';

describe('Authentication Integration Tests', () => {
  let storage: LevelDBAdapter;
  let app: any;
  let authConfig: AuthConfig;
  let adminCredentials: any;

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

    const testKey = crypto.randomBytes(32).toString('hex');
    const testDbPath = `/tmp/test-db-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    storage = new LevelDBAdapter(testKey, testDbPath);
    await storage.initialize(['tokyo-dc1']);
    app = createApp(storage, authConfig);

    // 管理者サービスを作成
    const adminRegistration = {
      serviceId: 'admin-service',
      serviceName: 'Admin Service',
      permissions: ['*'],
      isActive: true
    };

    // 直接AuthServiceを使用して管理者を作成
    const { AuthService } = require('../../../src/auth/services/auth-service');
    const authService = new AuthService(storage, authConfig);
    adminCredentials = await authService.registerService(adminRegistration);
  });

  afterEach(async () => {
    if (storage) {
      await storage.close();
    }
  });

  describe('Health Check', () => {
    it('should return health status without authentication', async () => {
      const res = await app.request('/health');
      
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.status).toBe('healthy');
      expect(data.version).toBe('1.0.0');
    });
  });

  describe('Service Registration', () => {
    it('should register new service with admin credentials', async () => {
      const token = AuthUtils.generateJWT(
        {
          sub: adminCredentials.serviceId,
          permissions: adminCredentials.permissions
        },
        authConfig
      );

      const newService = {
        serviceId: 'new-test-service',
        serviceName: 'New Test Service',
        permissions: ['logs:read', 'logs:write'],
        isActive: true
      };

      const res = await app.request('/admin/services', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newService)
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.serviceId).toBe('new-test-service');
      expect(data.credentials).toBeDefined();
      expect(data.credentials.apiKey).toBeDefined();
      expect(data.credentials.publicKey).toBeDefined();
      expect(data.credentials.privateKey).toBeDefined();
    });

    it('should reject service registration without admin permissions', async () => {
      // 通常のサービスを作成
      const normalService = {
        serviceId: 'normal-service',
        serviceName: 'Normal Service',
        permissions: ['logs:read'],
        isActive: true
      };

      const { AuthService } = require('../../../src/auth/services/auth-service');
      const authService = new AuthService(storage, authConfig);
      const normalCredentials = await authService.registerService(normalService);

      const token = AuthUtils.generateJWT(
        {
          sub: normalCredentials.serviceId,
          permissions: normalCredentials.permissions
        },
        authConfig
      );

      const newService = {
        serviceId: 'unauthorized-service',
        serviceName: 'Unauthorized Service',
        permissions: ['logs:read'],
        isActive: true
      };

      const res = await app.request('/admin/services', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newService)
      });

      expect(res.status).toBe(403);
    });
  });

  describe('Log API with JWT Authentication', () => {
    let serviceCredentials: any;

    beforeEach(async () => {
      // テスト用サービスを作成
      const token = AuthUtils.generateJWT(
        {
          sub: adminCredentials.serviceId,
          permissions: adminCredentials.permissions
        },
        authConfig
      );

      const testService = {
        serviceId: 'log-test-service',
        serviceName: 'Log Test Service',
        permissions: ['logs:read', 'logs:write'],
        isActive: true
      };

      const res = await app.request('/admin/services', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(testService)
      });

      const data = await res.json();
      serviceCredentials = data.credentials;
    });

    it('should create log with valid JWT token', async () => {
      const token = AuthUtils.generateJWT(
        {
          sub: serviceCredentials.serviceId,
          permissions: serviceCredentials.permissions
        },
        authConfig
      );

      const logEvent = {
        userId: 'test-user-123',
        eventType: 'user.login',
        data: { source: 'web' }
      };

      const res = await app.request('/api/logs', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(logEvent)
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.logId).toBeDefined();
      expect(data.timestamp).toBeDefined();
    });

    it('should reject log creation without authentication', async () => {
      const logEvent = {
        userId: 'test-user-123',
        eventType: 'user.login',
        data: { source: 'web' }
      };

      const res = await app.request('/api/logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(logEvent)
      });

      expect(res.status).toBe(401);
    });

    it('should reject log creation with insufficient permissions', async () => {
      // 読み取り専用権限のサービスを作成
      const token = AuthUtils.generateJWT(
        {
          sub: adminCredentials.serviceId,
          permissions: adminCredentials.permissions
        },
        authConfig
      );

      const readOnlyService = {
        serviceId: 'readonly-service',
        serviceName: 'Read Only Service',
        permissions: ['logs:read'],
        isActive: true
      };

      const regRes = await app.request('/admin/services', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(readOnlyService)
      });

      const regData = await regRes.json();
      const readOnlyCredentials = regData.credentials;

      const readOnlyToken = AuthUtils.generateJWT(
        {
          sub: readOnlyCredentials.serviceId,
          permissions: readOnlyCredentials.permissions
        },
        authConfig
      );

      const logEvent = {
        userId: 'test-user-123',
        eventType: 'user.login',
        data: { source: 'web' }
      };

      const res = await app.request('/api/logs', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${readOnlyToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(logEvent)
      });

      expect(res.status).toBe(403);
    });
  });

  describe('Log API with API Key Authentication', () => {
    let serviceCredentials: any;

    beforeEach(async () => {
      // テスト用サービスを作成
      const token = AuthUtils.generateJWT(
        {
          sub: adminCredentials.serviceId,
          permissions: adminCredentials.permissions
        },
        authConfig
      );

      const testService = {
        serviceId: 'apikey-test-service',
        serviceName: 'API Key Test Service',
        permissions: ['logs:read', 'logs:write'],
        isActive: true
      };

      const res = await app.request('/admin/services', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(testService)
      });

      const data = await res.json();
      serviceCredentials = data.credentials;
    });

    it('should create log with valid API key', async () => {
      const timestamp = Date.now();
      const nonce = AuthUtils.generateNonce();
      const method = 'POST';
      const path = '/api/logs';
      const logEvent = {
        userId: 'test-user-456',
        eventType: 'user.logout',
        data: { source: 'mobile' }
      };
      const body = JSON.stringify(logEvent);

      const signature = AuthUtils.generateApiKeySignature(
        serviceCredentials.apiKey,
        timestamp,
        nonce,
        authConfig.apiKeySecret,
        method,
        path,
        body
      );

      const res = await app.request('/api/logs', {
        method: 'POST',
        headers: {
          'X-API-Key': serviceCredentials.apiKey,
          'X-Signature': signature,
          'X-Timestamp': timestamp.toString(),
          'X-Nonce': nonce,
          'Content-Type': 'application/json'
        },
        body
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.logId).toBeDefined();
    });

    it('should reject API key with invalid signature', async () => {
      const timestamp = Date.now();
      const nonce = AuthUtils.generateNonce();
      const logEvent = {
        userId: 'test-user-456',
        eventType: 'user.logout',
        data: { source: 'mobile' }
      };

      const res = await app.request('/api/logs', {
        method: 'POST',
        headers: {
          'X-API-Key': serviceCredentials.apiKey,
          'X-Signature': 'invalid-signature',
          'X-Timestamp': timestamp.toString(),
          'X-Nonce': nonce,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(logEvent)
      });

      expect(res.status).toBe(401);
    });
  });

  describe('Authentication Test Endpoint', () => {
    it('should return authentication info for valid token', async () => {
      const token = AuthUtils.generateJWT(
        {
          sub: adminCredentials.serviceId,
          permissions: adminCredentials.permissions
        },
        authConfig
      );

      const res = await app.request('/api/auth/test', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.serviceId).toBe(adminCredentials.serviceId);
      expect(data.serviceName).toBe(adminCredentials.serviceName);
      expect(data.permissions).toEqual(adminCredentials.permissions);
      expect(data.method).toBe('jwt');
    });
  });
});

