// 認証方式の列挙
export enum AuthMethod {
  MTLS = 'mtls',
  JWT = 'jwt',
  API_KEY = 'api_key'
}

// サービス認証情報
export interface ServiceCredentials {
  serviceId: string;
  serviceName: string;
  publicKey?: string;
  privateKey?: string;
  apiKey?: string;
  permissions: string[];
  createdAt: number;
  expiresAt?: number;
}

// JWT ペイロード
export interface JWTPayload {
  sub: string; // サービスID
  iss: string; // 発行者
  aud: string; // 対象サービス
  exp: number; // 有効期限
  iat: number; // 発行時刻
  jti: string; // JWT ID
  permissions: string[];
  nonce?: string;
}

// API Key 認証情報
export interface ApiKeyAuth {
  apiKey: string;
  signature: string;
  timestamp: number;
  nonce: string;
}

// 認証結果
export interface AuthResult {
  success: boolean;
  serviceId?: string;
  serviceName?: string;
  permissions: string[];
  method: AuthMethod;
  error?: string;
  metadata?: Record<string, unknown>;
}

// 認証設定
export interface AuthConfig {
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
  jwtExpirationTime: string;
  apiKeySecret: string;
  nonceWindowMs: number;
  cacheExpirationMs: number;
  rateLimitPerMinute: number;
  enableMTLS: boolean;
  tlsCertPath?: string;
  tlsKeyPath?: string;
  tlsCaPath?: string;
}

// 認証コンテキスト
export interface AuthContext {
  serviceId: string;
  serviceName: string;
  permissions: string[];
  method: AuthMethod;
  authenticated: boolean;
  metadata: Record<string, unknown>;
}

// サービス登録情報
export interface ServiceRegistration {
  serviceId: string;
  serviceName: string;
  permissions: string[];
  publicKey?: string;
  apiKey?: string;
  isActive: boolean;
  createdAt: number;
  updatedAt: number;
}

// 認証ミドルウェアオプション
export interface AuthMiddlewareOptions {
  requiredPermissions?: string[];
  allowedMethods?: AuthMethod[];
  skipPaths?: string[];
  customValidator?: (context: AuthContext) => boolean;
}

