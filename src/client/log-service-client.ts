import { AuthUtils } from '../auth/utils/auth-utils';
import { AuthMethod, ServiceCredentials, AuthConfig } from '../auth/types';
import { LogEvent } from '../lifecycle/generation';

export interface ClientConfig {
  serviceCredentials: ServiceCredentials;
  targetUrl: string;
  authMethod: AuthMethod;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
}

export interface LogResponse {
  success: boolean;
  logId?: string;
  error?: string;
}

export class LogServiceClient {
  private config: ClientConfig;
  private jwtToken?: string | undefined;
  private jwtExpiry?: number | undefined;

  constructor(config: ClientConfig) {
    this.config = {
      timeout: 10000,
      retryAttempts: 3,
      retryDelay: 1000,
      ...config
    };
  }

  /**
   * ログを送信
   */
  async log(event: Omit<LogEvent, 'ipAddress' | 'countryCode'>): Promise<LogResponse> {
    const logEvent: LogEvent = {
      ...event,
      ipAddress: '127.0.0.1', // クライアント側では仮の値
      countryCode: 'JP' // クライアント側では仮の値
    };

    return this.makeRequest('/api/logs', 'POST', logEvent);
  }

  /**
   * ログを取得
   */
  async getLog(logId: string, dataCenter?: string): Promise<any> {
    const params = dataCenter ? `?dc=${dataCenter}` : '';
    const response = await this.makeRequest(`/api/logs/${logId}${params}`, 'GET');
    return response;
  }

  /**
   * ログを検索
   */
  async searchLogs(options: {
    dataCenter?: string;
    startTime?: number;
    endTime?: number;
    userId?: string;
  }): Promise<any> {
    const params = new URLSearchParams();
    if (options.dataCenter) params.append('dc', options.dataCenter);
    if (options.startTime) params.append('start', options.startTime.toString());
    if (options.endTime) params.append('end', options.endTime.toString());
    if (options.userId) params.append('userId', options.userId);

    const queryString = params.toString();
    const url = `/api/logs${queryString ? `?${queryString}` : ''}`;
    
    return this.makeRequest(url, 'GET');
  }

  /**
   * 保存統計を取得
   */
  async getRetentionStats(): Promise<any> {
    return this.makeRequest('/api/retention/stats', 'GET');
  }

  /**
   * HTTP リクエストを実行
   */
  private async makeRequest(
    path: string,
    method: string,
    body?: any
  ): Promise<any> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.config.retryAttempts!; attempt++) {
      try {
        const headers = await this.getAuthHeaders(method, path, body);
        const requestBody = body ? JSON.stringify(body) : undefined;

        const requestInit: RequestInit = {
          method,
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          signal: AbortSignal.timeout(this.config.timeout!)
        };

        if (requestBody) {
          requestInit.body = requestBody;
        }

        const response = await fetch(`${this.config.targetUrl}${path}`, requestInit);

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        return await response.json();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt < this.config.retryAttempts! - 1) {
          await this.delay(this.config.retryDelay! * Math.pow(2, attempt));
        }
      }
    }

    throw lastError || new Error('Request failed after all retry attempts');
  }

  /**
   * 認証ヘッダーを生成
   */
  private async getAuthHeaders(
    method: string,
    path: string,
    body?: any
  ): Promise<Record<string, string>> {
    switch (this.config.authMethod) {
      case AuthMethod.JWT:
        return this.getJWTHeaders();
      
      case AuthMethod.API_KEY:
        return this.getApiKeyHeaders(method, path, body);
      
      case AuthMethod.MTLS:
        return this.getMTLSHeaders();
      
      default:
        throw new Error(`Unsupported auth method: ${this.config.authMethod}`);
    }
  }

  /**
   * JWT 認証ヘッダーを生成
   */
  private getJWTHeaders(): Record<string, string> {
    if (!this.jwtToken || !this.jwtExpiry || Date.now() > this.jwtExpiry) {
      this.generateJWTToken();
    }

    return {
      'Authorization': `Bearer ${this.jwtToken}`
    };
  }

  /**
   * API Key 認証ヘッダーを生成
   */
  private getApiKeyHeaders(
    method: string,
    path: string,
    body?: any
  ): Record<string, string> {
    const timestamp = Date.now();
    const nonce = AuthUtils.generateNonce();
    const bodyString = body ? JSON.stringify(body) : undefined;

    const signature = AuthUtils.generateApiKeySignature(
      this.config.serviceCredentials.apiKey!,
      timestamp,
      nonce,
      'your-api-key-secret', // 実際の実装では設定から取得
      method,
      path,
      bodyString
    );

    return {
      'X-API-Key': this.config.serviceCredentials.apiKey!,
      'X-Signature': signature,
      'X-Timestamp': timestamp.toString(),
      'X-Nonce': nonce
    };
  }

  /**
   * mTLS 認証ヘッダーを生成
   */
  private getMTLSHeaders(): Record<string, string> {
    // 実際の実装では、クライアント証明書を設定
    return {
      'X-Client-Cert': this.config.serviceCredentials.publicKey || ''
    };
  }

  /**
   * JWT トークンを生成
   */
  private generateJWTToken(): void {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 3600; // 1時間

    const payload = {
      sub: this.config.serviceCredentials.serviceId,
      iss: 'log-service',
      aud: 'log-service',
      permissions: this.config.serviceCredentials.permissions,
      nonce: AuthUtils.generateNonce()
    };

    // 実際の実装では、適切な設定を使用
    const config: AuthConfig = {
      jwtSecret: 'your-jwt-secret',
      jwtIssuer: 'log-service',
      jwtAudience: 'log-service',
      jwtExpirationTime: '1h',
      apiKeySecret: 'your-api-key-secret',
      nonceWindowMs: 300000,
      cacheExpirationMs: 300000,
      rateLimitPerMinute: 1000,
      enableMTLS: false
    };

    this.jwtToken = AuthUtils.generateJWT(payload, config);
    this.jwtExpiry = exp * 1000; // ミリ秒に変換
  }

  /**
   * 遅延処理
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * 接続テスト
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.makeRequest('/health', 'GET');
      return response.status === 'healthy';
    } catch (error) {
      return false;
    }
  }

  /**
   * 認証情報をローテーション
   */
  async rotateCredentials(): Promise<ServiceCredentials> {
    const response = await this.makeRequest(
      `/admin/services/${this.config.serviceCredentials.serviceId}/rotate`,
      'POST'
    );

    // 新しい認証情報で設定を更新
    this.config.serviceCredentials = response;
    this.jwtToken = undefined;
    this.jwtExpiry = undefined;

    return response;
  }
}

