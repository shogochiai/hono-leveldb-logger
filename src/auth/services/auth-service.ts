import { LevelDBAdapter } from '../../storage/leveldb-adapter';
import { AuthUtils } from '../utils/auth-utils';
import {
  ServiceCredentials,
  ServiceRegistration,
  AuthConfig,
  AuthResult,
  AuthMethod,
  ApiKeyAuth
} from '../types';

export class AuthService {
  private storage: LevelDBAdapter;
  private config: AuthConfig;
  private cache: Map<string, { result: AuthResult; expiry: number }>;

  constructor(storage: LevelDBAdapter, config: AuthConfig) {
    this.storage = storage;
    this.config = config;
    this.cache = new Map();
    
    // キャッシュクリーンアップを定期実行
    setInterval(() => this.cleanupCache(), 60000); // 1分ごと
  }

  /**
   * サービスを登録
   */
  async registerService(registration: Omit<ServiceRegistration, 'createdAt' | 'updatedAt'>): Promise<ServiceCredentials> {
    const now = Date.now();
    const { publicKey, privateKey } = AuthUtils.generateKeyPair();
    const apiKey = AuthUtils.generateSecureRandom(32);

    const serviceRegistration: ServiceRegistration = {
      ...registration,
      publicKey,
      apiKey,
      createdAt: now,
      updatedAt: now
    };

    const credentials: ServiceCredentials = {
      serviceId: registration.serviceId,
      serviceName: registration.serviceName,
      publicKey,
      privateKey,
      apiKey,
      permissions: registration.permissions,
      createdAt: now
    };

    // ストレージに保存
    await this.storage.store(
      {
        id: `service:${registration.serviceId}`,
        timestamp: now,
        userId: 'system',
        eventType: 'service.registration',
        ipAddress: '127.0.0.1',
        countryCode: 'SYSTEM',
        data: serviceRegistration as unknown as Record<string, unknown>
      },
      'tokyo-dc1'
    );

    return credentials;
  }

  /**
   * JWT トークンで認証
   */
  async authenticateJWT(token: string): Promise<AuthResult> {
    const cacheKey = `jwt:${AuthUtils.hash(token)}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached && cached.expiry > Date.now()) {
      return cached.result;
    }

    try {
      const payload = AuthUtils.verifyJWT(token, this.config);
      
      // サービス情報を取得
      const service = await this.getServiceRegistration(payload.sub);
      if (!service || !service.isActive) {
        return this.createFailureResult('Service not found or inactive', AuthMethod.JWT);
      }

      // Nonce チェック（リプレイ攻撃防止）
      if (payload.nonce && !(await this.isNonceValid(payload.nonce))) {
        return this.createFailureResult('Invalid nonce', AuthMethod.JWT);
      }

      const result: AuthResult = {
        success: true,
        serviceId: service.serviceId,
        serviceName: service.serviceName,
        permissions: payload.permissions,
        method: AuthMethod.JWT,
        metadata: {
          jti: payload.jti,
          exp: payload.exp
        }
      };

      // キャッシュに保存
      this.cache.set(cacheKey, {
        result,
        expiry: Date.now() + this.config.cacheExpirationMs
      });

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return this.createFailureResult(`JWT authentication failed: ${errorMessage}`, AuthMethod.JWT);
    }
  }

  /**
   * API Key で認証
   */
  async authenticateApiKey(
    auth: ApiKeyAuth,
    method: string,
    path: string,
    body?: string
  ): Promise<AuthResult> {
    const cacheKey = `apikey:${auth.apiKey}:${auth.nonce}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached && cached.expiry > Date.now()) {
      return cached.result;
    }

    try {
      // タイムスタンプ検証
      if (!AuthUtils.isTimestampValid(auth.timestamp, this.config.nonceWindowMs)) {
        return this.createFailureResult('Invalid timestamp', AuthMethod.API_KEY);
      }

      // Nonce 検証
      if (!(await this.isNonceValid(auth.nonce))) {
        return this.createFailureResult('Invalid nonce', AuthMethod.API_KEY);
      }

      // サービス情報を取得
      const service = await this.getServiceByApiKey(auth.apiKey);
      if (!service || !service.isActive) {
        return this.createFailureResult('Invalid API key', AuthMethod.API_KEY);
      }

      // 署名検証
      if (!AuthUtils.verifyApiKeySignature(auth, this.config.apiKeySecret, method, path, body)) {
        return this.createFailureResult('Invalid signature', AuthMethod.API_KEY);
      }

      const result: AuthResult = {
        success: true,
        serviceId: service.serviceId,
        serviceName: service.serviceName,
        permissions: service.permissions,
        method: AuthMethod.API_KEY,
        metadata: {
          timestamp: auth.timestamp,
          nonce: auth.nonce
        }
      };

      // Nonce を使用済みとしてマーク
      await this.markNonceUsed(auth.nonce);

      // キャッシュに保存
      this.cache.set(cacheKey, {
        result,
        expiry: Date.now() + this.config.cacheExpirationMs
      });

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return this.createFailureResult(`API Key authentication failed: ${errorMessage}`, AuthMethod.API_KEY);
    }
  }

  /**
   * mTLS で認証
   */
  async authenticateMTLS(clientCert: string): Promise<AuthResult> {
    try {
      // クライアント証明書から情報を抽出
      const serviceId = this.extractServiceIdFromCert(clientCert);
      
      const service = await this.getServiceRegistration(serviceId);
      if (!service || !service.isActive) {
        return this.createFailureResult('Service not found or inactive', AuthMethod.MTLS);
      }

      return {
        success: true,
        serviceId: service.serviceId,
        serviceName: service.serviceName,
        permissions: service.permissions,
        method: AuthMethod.MTLS,
        metadata: {
          clientCert: clientCert.substring(0, 100) + '...' // ログ用に短縮
        }
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return this.createFailureResult(`mTLS authentication failed: ${errorMessage}`, AuthMethod.MTLS);
    }
  }

  /**
   * サービス認証情報をローテーション
   */
  async rotateServiceCredentials(serviceId: string): Promise<ServiceCredentials> {
    const service = await this.getServiceRegistration(serviceId);
    if (!service) {
      throw new Error('Service not found');
    }

    const { publicKey, privateKey } = AuthUtils.generateKeyPair();
    const apiKey = AuthUtils.generateSecureRandom(32);
    const now = Date.now();

    const updatedService: ServiceRegistration = {
      ...service,
      publicKey,
      apiKey,
      updatedAt: now
    };

    // ストレージを更新
    await this.storage.store(
      {
        id: `service:${serviceId}`,
        timestamp: now,
        userId: 'system',
        eventType: 'service.credential_rotation',
        ipAddress: '127.0.0.1',
        countryCode: 'SYSTEM',
        data: updatedService as unknown as Record<string, unknown>
      },
      'tokyo-dc1'
    );

    // キャッシュをクリア
    this.clearServiceCache(serviceId);

    return {
      serviceId: service.serviceId,
      serviceName: service.serviceName,
      publicKey,
      privateKey,
      apiKey,
      permissions: service.permissions,
      createdAt: service.createdAt
    };
  }

  /**
   * サービス登録情報を取得
   */
  private async getServiceRegistration(serviceId: string): Promise<ServiceRegistration | null> {
    try {
      const log = await this.storage.retrieve(`service:${serviceId}`, 'tokyo-dc1');
      return log?.data as unknown as ServiceRegistration | null;
    } catch (error) {
      return null;
    }
  }

  /**
   * API Key でサービスを検索
   */
  private async getServiceByApiKey(apiKey: string): Promise<ServiceRegistration | null> {
    // 実際の実装では、API Key のインデックスを使用
    // ここでは簡略化のため、全サービスを検索
    const services = await this.storage.query({ dataCenter: 'tokyo-dc1' });
    
    for (const log of services) {
      if (log.eventType === 'service.registration' || log.eventType === 'service.credential_rotation') {
        const service = log.data as unknown as ServiceRegistration;
        if (service.apiKey === apiKey) {
          return service;
        }
      }
    }
    
    return null;
  }

  /**
   * Nonce の有効性をチェック
   */
  private async isNonceValid(nonce: string): Promise<boolean> {
    try {
      const log = await this.storage.retrieve(`nonce:${nonce}`, 'tokyo-dc1');
      return !log; // 使用済みでなければ有効
    } catch (error) {
      return true; // エラーの場合は有効とみなす
    }
  }

  /**
   * Nonce を使用済みとしてマーク
   */
  private async markNonceUsed(nonce: string): Promise<void> {
    await this.storage.store(
      {
        id: `nonce:${nonce}`,
        timestamp: Date.now(),
        userId: 'system',
        eventType: 'nonce.used',
        ipAddress: '127.0.0.1',
        countryCode: 'SYSTEM',
        data: { nonce, usedAt: Date.now() }
      },
      'tokyo-dc1'
    );
  }

  /**
   * クライアント証明書からサービスIDを抽出
   */
  private extractServiceIdFromCert(clientCert: string): string {
    // 実際の実装では、証明書のCNやSANからサービスIDを抽出
    // ここでは簡略化
    const match = clientCert.match(/CN=([^,]+)/);
    if (!match) {
      throw new Error('Cannot extract service ID from certificate');
    }
    return match[1];
  }

  /**
   * 失敗結果を作成
   */
  private createFailureResult(error: string, method: AuthMethod): AuthResult {
    return {
      success: false,
      permissions: [],
      method,
      error
    };
  }

  /**
   * サービスのキャッシュをクリア
   */
  private clearServiceCache(serviceId: string): void {
    for (const [key] of this.cache) {
      if (key.includes(serviceId)) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * 期限切れキャッシュをクリーンアップ
   */
  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, value] of this.cache) {
      if (value.expiry <= now) {
        this.cache.delete(key);
      }
    }
  }
}

