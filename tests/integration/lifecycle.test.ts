import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { LevelDBAdapter } from '../../src/storage/leveldb-adapter';
import { LogGenerator } from '../../src/lifecycle/generation';
import { DeletionManager } from '../../src/lifecycle/deletion';
import { RetentionManager } from '../../src/lifecycle/retention';
import { AuthService } from '../../src/auth/services/auth-service';
import { AuthConfig } from '../../src/auth/types';
import crypto from 'crypto';

describe('Log Lifecycle Integration with Authentication', () => {
  let storage: LevelDBAdapter;
  let generator: LogGenerator;
  let deletionManager: DeletionManager;
  let retentionManager: RetentionManager;
  let authService: AuthService;
  let authConfig: AuthConfig;
  let testServiceCredentials: any;
  
  beforeAll(async () => {
    // 認証設定
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

    // テスト用の暗号化キーを生成（64文字の16進数文字列）
    const testKey = crypto.randomBytes(32).toString('hex');
    const testDbPath = `/tmp/test-db-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    storage = new LevelDBAdapter(testKey, testDbPath);
    await storage.initialize(['tokyo-dc1']);
    
    generator = new LogGenerator(storage);
    deletionManager = new DeletionManager(storage);
    retentionManager = new RetentionManager(storage);
    authService = new AuthService(storage, authConfig);

    // テスト用サービスを登録
    const serviceRegistration = {
      serviceId: 'integration-test-service',
      serviceName: 'Integration Test Service',
      permissions: ['logs:read', 'logs:write'],
      isActive: true
    };

    testServiceCredentials = await authService.registerService(serviceRegistration);
  });
  
  afterAll(async () => {
    if (storage) {
      await storage.close();
    }
  });
  
  it('should complete full log lifecycle with service context', async () => {
    // ログ生成（サービス情報を含む）
    const log = await generator.generateLog({
      userId: 'test-user',
      eventType: 'test-event',
      ipAddress: '127.0.0.1',
      countryCode: 'JP',
      data: { 
        test: true, 
        message: 'integration test',
        _serviceId: testServiceCredentials.serviceId,
        _serviceName: testServiceCredentials.serviceName
      }
    });
    
    expect(log.id).toBeDefined();
    expect(log.timestamp).toBeGreaterThan(0);
    expect(log.userId).toBe('test-user');
    expect(log.data._serviceId).toBe(testServiceCredentials.serviceId);
    
    // ログ取得
    const retrieved = await storage.retrieve(log.id, 'tokyo-dc1');
    expect(retrieved).toBeDefined();
    expect(retrieved?.data.test).toBe(true);
    expect(retrieved?.data.message).toBe('integration test');
    expect(retrieved?.data._serviceId).toBe(testServiceCredentials.serviceId);
    
    // 保存統計の確認
    const stats = await retentionManager.monitorRetention();
    expect(stats.total).toBeGreaterThan(0);
    expect(stats.retained).toBeGreaterThan(0);
    expect(stats.byCountry['JP']).toBeGreaterThan(0);
  });
  
  it('should handle batch log generation with service context', async () => {
    const events = [
      {
        userId: 'batch-user-1',
        eventType: 'batch-event',
        ipAddress: '127.0.0.1',
        countryCode: 'US',
        data: { 
          batch: true, 
          index: 1,
          _serviceId: testServiceCredentials.serviceId,
          _serviceName: testServiceCredentials.serviceName
        }
      },
      {
        userId: 'batch-user-2',
        eventType: 'batch-event',
        ipAddress: '127.0.0.1',
        countryCode: 'EU',
        data: { 
          batch: true, 
          index: 2,
          _serviceId: testServiceCredentials.serviceId,
          _serviceName: testServiceCredentials.serviceName
        }
      }
    ];
    
    const logs = await generator.generateBatch(events);
    expect(logs).toHaveLength(2);
    expect(logs[0].userId).toBe('batch-user-1');
    expect(logs[1].userId).toBe('batch-user-2');
    expect(logs[0].data._serviceId).toBe(testServiceCredentials.serviceId);
    expect(logs[1].data._serviceId).toBe(testServiceCredentials.serviceId);
  });
  
  it('should query logs with service filtering', async () => {
    // 特定サービスのログを検索
    const serviceLogs = await storage.query({
      dataCenter: 'tokyo-dc1'
    });
    
    const filteredLogs = serviceLogs.filter(log => 
      log.data._serviceId === testServiceCredentials.serviceId
    );
    
    expect(filteredLogs.length).toBeGreaterThan(0);
    expect(filteredLogs.every(log => 
      log.data._serviceId === testServiceCredentials.serviceId
    )).toBe(true);
  });
  
  it('should handle authentication methods', async () => {
    const { AuthUtils } = require('../../src/auth/utils/auth-utils');

    // JWT認証テスト
    const jwtPayload = {
      sub: testServiceCredentials.serviceId,
      permissions: testServiceCredentials.permissions
    };

    const token = AuthUtils.generateJWT(jwtPayload, authConfig);
    const jwtResult = await authService.authenticateJWT(token);
    
    expect(jwtResult.success).toBe(true);
    expect(jwtResult.serviceId).toBe(testServiceCredentials.serviceId);
    expect(jwtResult.serviceName).toBe(testServiceCredentials.serviceName);

    // API Key認証テスト
    const timestamp = Date.now();
    const nonce = AuthUtils.generateNonce();
    const signature = AuthUtils.generateApiKeySignature(
      testServiceCredentials.apiKey,
      timestamp,
      nonce,
      authConfig.apiKeySecret,
      'POST',
      '/api/logs'
    );

    const apiKeyAuth = {
      apiKey: testServiceCredentials.apiKey,
      signature,
      timestamp,
      nonce
    };

    const apiKeyResult = await authService.authenticateApiKey(
      apiKeyAuth,
      'POST',
      '/api/logs'
    );

    expect(apiKeyResult.success).toBe(true);
    expect(apiKeyResult.serviceId).toBe(testServiceCredentials.serviceId);
  });
  
  it('should handle encryption and decryption with service context', async () => {
    const sensitiveData = {
      creditCard: '4111-1111-1111-1111',
      ssn: '123-45-6789',
      personalInfo: 'sensitive information',
      _serviceId: testServiceCredentials.serviceId,
      _serviceName: testServiceCredentials.serviceName
    };
    
    const log = await generator.generateLog({
      userId: 'sensitive-user',
      eventType: 'payment',
      ipAddress: '127.0.0.1',
      countryCode: 'JP', // tokyo-dc1に対応
      data: sensitiveData
    });
    
    const retrieved = await storage.retrieve(log.id, 'tokyo-dc1');
    expect(retrieved?.data.creditCard).toBe(sensitiveData.creditCard);
    expect(retrieved?.data.ssn).toBe(sensitiveData.ssn);
    expect(retrieved?.data.personalInfo).toBe(sensitiveData.personalInfo);
    expect(retrieved?.data._serviceId).toBe(testServiceCredentials.serviceId);
  });

  it('should handle service credential rotation', async () => {
    // 認証情報をローテーション
    const newCredentials = await authService.rotateServiceCredentials(
      testServiceCredentials.serviceId
    );

    expect(newCredentials.serviceId).toBe(testServiceCredentials.serviceId);
    expect(newCredentials.serviceName).toBe(testServiceCredentials.serviceName);
    expect(newCredentials.apiKey).not.toBe(testServiceCredentials.apiKey);
    expect(newCredentials.publicKey).not.toBe(testServiceCredentials.publicKey);
    expect(newCredentials.privateKey).not.toBe(testServiceCredentials.privateKey);

    // 新しい認証情報でのテスト
    const { AuthUtils } = require('../../src/auth/utils/auth-utils');
    const timestamp = Date.now();
    const nonce = AuthUtils.generateNonce();
    const signature = AuthUtils.generateApiKeySignature(
      newCredentials.apiKey,
      timestamp,
      nonce,
      authConfig.apiKeySecret,
      'POST',
      '/api/logs'
    );

    const apiKeyAuth = {
      apiKey: newCredentials.apiKey,
      signature,
      timestamp,
      nonce
    };

    const result = await authService.authenticateApiKey(
      apiKeyAuth,
      'POST',
      '/api/logs'
    );

    expect(result.success).toBe(true);
    expect(result.serviceId).toBe(testServiceCredentials.serviceId);

    // 古い認証情報は無効になっている
    const oldAuth = {
      apiKey: testServiceCredentials.apiKey,
      signature: 'old-signature',
      timestamp: Date.now(),
      nonce: AuthUtils.generateNonce()
    };

    const oldResult = await authService.authenticateApiKey(
      oldAuth,
      'POST',
      '/api/logs'
    );

    expect(oldResult.success).toBe(false);
  });
});

