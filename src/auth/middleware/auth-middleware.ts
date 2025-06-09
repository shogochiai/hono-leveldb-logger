import { Context, Next } from 'hono';
import { AuthService } from '../services/auth-service';
import { AuthUtils } from '../utils/auth-utils';
import {
  AuthMethod,
  AuthResult,
  AuthContext,
  AuthMiddlewareOptions,
  ApiKeyAuth
} from '../types';

export class AuthMiddleware {
  private authService: AuthService;
  private rateLimitMap: Map<string, { count: number; resetTime: number }>;

  constructor(authService: AuthService) {
    this.authService = authService;
    this.rateLimitMap = new Map();
    
    // レート制限のクリーンアップを定期実行
    setInterval(() => this.cleanupRateLimit(), 60000); // 1分ごと
  }

  /**
   * 認証ミドルウェア
   */
  authenticate(options: AuthMiddlewareOptions = {}) {
    return async (c: Context, next: Next) => {
      const path = c.req.path;
      
      // スキップパスのチェック
      if (options.skipPaths?.some(skipPath => path.startsWith(skipPath))) {
        return next();
      }

      try {
        // 認証を実行
        const authResult = await this.performAuthentication(c, options);
        
        if (!authResult.success) {
          return c.json({ error: authResult.error }, 401);
        }

        // レート制限チェック
        if (!(await this.checkRateLimit(authResult.serviceId!))) {
          return c.json({ error: 'Rate limit exceeded' }, 429);
        }

        // 権限チェック
        if (options.requiredPermissions && 
            !AuthUtils.hasPermission(authResult.permissions, options.requiredPermissions)) {
          return c.json({ error: 'Insufficient permissions' }, 403);
        }

        // カスタムバリデーション
        if (options.customValidator) {
          const authContext: AuthContext = {
            serviceId: authResult.serviceId!,
            serviceName: authResult.serviceName!,
            permissions: authResult.permissions,
            method: authResult.method,
            authenticated: true,
            metadata: authResult.metadata || {}
          };

          if (!options.customValidator(authContext)) {
            return c.json({ error: 'Custom validation failed' }, 403);
          }
        }

        // 認証情報をコンテキストに設定
        c.set('auth', authResult);
        c.set('serviceId', authResult.serviceId);
        c.set('permissions', authResult.permissions);

        return next();
      } catch (error) {
        console.error('Authentication middleware error:', error);
        return c.json({ error: 'Authentication failed' }, 500);
      }
    };
  }

  /**
   * 管理者認証ミドルウェア
   */
  requireAdmin() {
    return this.authenticate({
      requiredPermissions: ['admin:*'],
      customValidator: (context) => {
        return context.permissions.includes('admin:*') || 
               context.permissions.includes('*');
      }
    });
  }

  /**
   * 特定の権限を要求するミドルウェア
   */
  requirePermissions(permissions: string[]) {
    return this.authenticate({
      requiredPermissions: permissions
    });
  }

  /**
   * 認証を実行
   */
  private async performAuthentication(
    c: Context, 
    options: AuthMiddlewareOptions
  ): Promise<AuthResult> {
    const allowedMethods = options.allowedMethods || [
      AuthMethod.JWT,
      AuthMethod.API_KEY,
      AuthMethod.MTLS
    ];

    // JWT 認証を試行
    if (allowedMethods.includes(AuthMethod.JWT)) {
      const jwtResult = await this.tryJWTAuth(c);
      if (jwtResult.success) return jwtResult;
    }

    // API Key 認証を試行
    if (allowedMethods.includes(AuthMethod.API_KEY)) {
      const apiKeyResult = await this.tryApiKeyAuth(c);
      if (apiKeyResult.success) return apiKeyResult;
    }

    // mTLS 認証を試行
    if (allowedMethods.includes(AuthMethod.MTLS)) {
      const mtlsResult = await this.tryMTLSAuth(c);
      if (mtlsResult.success) return mtlsResult;
    }

    return {
      success: false,
      permissions: [],
      method: AuthMethod.JWT,
      error: 'No valid authentication method found'
    };
  }

  /**
   * JWT 認証を試行
   */
  private async tryJWTAuth(c: Context): Promise<AuthResult> {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        success: false,
        permissions: [],
        method: AuthMethod.JWT,
        error: 'Missing or invalid Authorization header'
      };
    }

    const token = authHeader.substring(7);
    return this.authService.authenticateJWT(token);
  }

  /**
   * API Key 認証を試行
   */
  private async tryApiKeyAuth(c: Context): Promise<AuthResult> {
    const apiKey = c.req.header('X-API-Key');
    const signature = c.req.header('X-Signature');
    const timestamp = c.req.header('X-Timestamp');
    const nonce = c.req.header('X-Nonce');

    if (!apiKey || !signature || !timestamp || !nonce) {
      return {
        success: false,
        permissions: [],
        method: AuthMethod.API_KEY,
        error: 'Missing API Key authentication headers'
      };
    }

    const auth: ApiKeyAuth = {
      apiKey,
      signature,
      timestamp: parseInt(timestamp),
      nonce
    };

    const method = c.req.method;
    const path = c.req.path;
    const body = method !== 'GET' ? await c.req.text() : undefined;

    return this.authService.authenticateApiKey(auth, method, path, body);
  }

  /**
   * mTLS 認証を試行
   */
  private async tryMTLSAuth(c: Context): Promise<AuthResult> {
    // クライアント証明書を取得
    const clientCert = c.req.header('X-Client-Cert');
    if (!clientCert) {
      return {
        success: false,
        permissions: [],
        method: AuthMethod.MTLS,
        error: 'Missing client certificate'
      };
    }

    return this.authService.authenticateMTLS(clientCert);
  }

  /**
   * レート制限をチェック
   */
  private async checkRateLimit(serviceId: string): Promise<boolean> {
    const key = `rate_limit:${serviceId}`;
    const now = Date.now();
    const windowMs = 60000; // 1分
    
    let rateLimit = this.rateLimitMap.get(key);
    
    if (!rateLimit || now > rateLimit.resetTime) {
      rateLimit = {
        count: 0,
        resetTime: now + windowMs
      };
      this.rateLimitMap.set(key, rateLimit);
    }

    rateLimit.count++;
    
    // レート制限を超えているかチェック
    return rateLimit.count <= 1000; // 1分間に1000リクエスト
  }

  /**
   * レート制限のクリーンアップ
   */
  private cleanupRateLimit(): void {
    const now = Date.now();
    for (const [key, value] of this.rateLimitMap) {
      if (now > value.resetTime) {
        this.rateLimitMap.delete(key);
      }
    }
  }
}

/**
 * 認証コンテキストを取得するヘルパー関数
 */
export function getAuthContext(c: Context): AuthResult | null {
  return c.get('auth') || null;
}

/**
 * サービスIDを取得するヘルパー関数
 */
export function getServiceId(c: Context): string | null {
  return c.get('serviceId') || null;
}

/**
 * 権限を取得するヘルパー関数
 */
export function getPermissions(c: Context): string[] {
  return c.get('permissions') || [];
}

