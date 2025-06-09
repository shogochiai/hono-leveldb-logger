import { LevelDBAdapter } from './storage/leveldb-adapter';
import { createApp } from './api/routes';
import { DeletionManager } from './lifecycle/deletion';
import { AuthConfig } from './auth/types';

// エクスポート
export { LogEntry, LogId, UserId, CountryCode, Timestamp } from './core/sets';
export { LogEvent, LogGenerator } from './lifecycle/generation';
export { RetentionManager } from './lifecycle/retention';
export { DeletionManager } from './lifecycle/deletion';
export { LevelDBAdapter } from './storage/leveldb-adapter';
export { createApp } from './api/routes';
export { LogServiceClient } from './client/log-service-client';
export { AuthService } from './auth/services/auth-service';
export { AuthMiddleware } from './auth/middleware/auth-middleware';
export { AuthUtils } from './auth/utils/auth-utils';
export * from './auth/types';

// デフォルトエクスポート
export default {
  LevelDBAdapter,
  createApp,
  LogGenerator: require('./lifecycle/generation').LogGenerator,
  RetentionManager: require('./lifecycle/retention').RetentionManager,
  DeletionManager: require('./lifecycle/deletion').DeletionManager,
  AuthService: require('./auth/services/auth-service').AuthService,
  LogServiceClient: require('./client/log-service-client').LogServiceClient
};

// デフォルト認証設定
export function getDefaultAuthConfig(): AuthConfig {
  const config: AuthConfig = {
    jwtSecret: process.env.JWT_SECRET || 'your-jwt-secret-change-in-production',
    jwtIssuer: process.env.JWT_ISSUER || 'hono-leveldb-logger',
    jwtAudience: process.env.JWT_AUDIENCE || 'hono-leveldb-logger',
    jwtExpirationTime: process.env.JWT_EXPIRATION || '1h',
    apiKeySecret: process.env.API_KEY_SECRET || 'your-api-key-secret-change-in-production',
    nonceWindowMs: parseInt(process.env.NONCE_WINDOW_MS || '300000'), // 5分
    cacheExpirationMs: parseInt(process.env.CACHE_EXPIRATION_MS || '300000'), // 5分
    rateLimitPerMinute: parseInt(process.env.RATE_LIMIT_PER_MINUTE || '1000'),
    enableMTLS: process.env.ENABLE_MTLS === 'true'
  };

  if (process.env.TLS_CERT_PATH) {
    config.tlsCertPath = process.env.TLS_CERT_PATH;
  }
  if (process.env.TLS_KEY_PATH) {
    config.tlsKeyPath = process.env.TLS_KEY_PATH;
  }
  if (process.env.TLS_CA_PATH) {
    config.tlsCaPath = process.env.TLS_CA_PATH;
  }

  return config;
}

// サーバー起動関数
export async function startServer(port: number = 3000, encryptionKey?: string, authConfig?: AuthConfig) {
  const key = encryptionKey || process.env.ENCRYPTION_KEY || 'default-key-for-development-only';
  const config = authConfig || getDefaultAuthConfig();
  
  // ストレージ初期化
  const storage = new LevelDBAdapter(key);
  await storage.initialize(['tokyo-dc1', 'virginia-dc1', 'frankfurt-dc1']);
  
  // アプリケーション作成
  const app = createApp(storage, config);
  
  // 自動削除スケジュール開始
  const deletionManager = new DeletionManager(storage);
  deletionManager.scheduleAutoDeletion(24); // 24時間ごと
  
  console.log(`Server starting on port ${port}`);
  console.log('Authentication methods enabled:');
  console.log('- JWT Token Authentication');
  console.log('- API Key + HMAC Authentication');
  if (config.enableMTLS) {
    console.log('- mTLS Authentication');
  }
  
  return {
    app,
    storage,
    deletionManager,
    authConfig: config
  };
}

// 開発用のクイックスタート関数
export async function quickStart(options: {
  port?: number;
  encryptionKey?: string;
  createAdminService?: boolean;
} = {}) {
  const { port = 3000, encryptionKey, createAdminService = true } = options;
  
  const { app, storage, authConfig } = await startServer(port, encryptionKey);
  
  if (createAdminService) {
    // 開発用の管理者サービスを作成
    const { AuthService } = require('./auth/services/auth-service');
    const authService = new AuthService(storage, authConfig);
    
    try {
      const adminCredentials = await authService.registerService({
        serviceId: 'admin-service',
        serviceName: 'Admin Service',
        permissions: ['*'],
        isActive: true
      });
      
      console.log('\n🔑 Admin Service Created:');
      console.log('Service ID:', adminCredentials.serviceId);
      console.log('API Key:', adminCredentials.apiKey);
      console.log('Permissions:', adminCredentials.permissions);
      console.log('\nUse these credentials to register other services via /admin/services endpoint');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.warn('Failed to create admin service:', errorMessage);
    }
  }
  
  return { app, storage, authConfig };
}

