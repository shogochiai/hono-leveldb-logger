import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { JWTPayload, ApiKeyAuth, AuthConfig } from '../types';

export class AuthUtils {
  /**
   * JWT トークンを生成
   */
  static generateJWT(
    payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>,
    config: AuthConfig
  ): string {
    const now = Math.floor(Date.now() / 1000);
    const fullPayload: JWTPayload = {
      ...payload,
      iat: now,
      exp: now + this.parseExpirationTime(config.jwtExpirationTime),
      jti: crypto.randomUUID(),
      iss: config.jwtIssuer,
      aud: config.jwtAudience
    };

    return jwt.sign(fullPayload, config.jwtSecret, { algorithm: 'HS256' });
  }

  /**
   * JWT トークンを検証
   */
  static verifyJWT(token: string, config: AuthConfig): JWTPayload {
    try {
      const decoded = jwt.verify(token, config.jwtSecret, {
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
        algorithms: ['HS256']
      }) as JWTPayload;

      return decoded;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`JWT verification failed: ${errorMessage}`);
    }
  }

  /**
   * API Key 署名を生成
   */
  static generateApiKeySignature(
    apiKey: string,
    timestamp: number,
    nonce: string,
    secret: string,
    method: string = 'POST',
    path: string = '/api/logs',
    body?: string
  ): string {
    const message = [
      method.toUpperCase(),
      path,
      apiKey,
      timestamp.toString(),
      nonce,
      body || ''
    ].join('\n');

    return crypto
      .createHmac('sha256', secret)
      .update(message)
      .digest('hex');
  }

  /**
   * API Key 署名を検証
   */
  static verifyApiKeySignature(
    auth: ApiKeyAuth,
    secret: string,
    method: string = 'POST',
    path: string = '/api/logs',
    body?: string
  ): boolean {
    try {
      const expectedSignature = this.generateApiKeySignature(
        auth.apiKey,
        auth.timestamp,
        auth.nonce,
        secret,
        method,
        path,
        body
      );

      // バッファ長を揃えるため、両方を同じ長さにパディング
      const authSigBuffer = Buffer.from(auth.signature.padEnd(64, '0'), 'hex');
      const expectedSigBuffer = Buffer.from(expectedSignature.padEnd(64, '0'), 'hex');

      return crypto.timingSafeEqual(authSigBuffer, expectedSigBuffer);
    } catch (error) {
      return false;
    }
  }

  /**
   * Nonce を生成
   */
  static generateNonce(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * タイムスタンプの有効性を検証
   */
  static isTimestampValid(
    timestamp: number,
    windowMs: number = 300000 // 5分
  ): boolean {
    const now = Date.now();
    const diff = Math.abs(now - timestamp);
    return diff <= windowMs;
  }

  /**
   * 権限をチェック
   */
  static hasPermission(
    userPermissions: string[],
    requiredPermissions: string[]
  ): boolean {
    if (requiredPermissions.length === 0) return true;
    
    return requiredPermissions.every(required => {
      // ワイルドカード権限をチェック
      if (userPermissions.includes('*')) return true;
      
      // 完全一致をチェック
      if (userPermissions.includes(required)) return true;
      
      // パターンマッチング (例: logs:* が logs:read にマッチ)
      return userPermissions.some(permission => {
        if (permission.endsWith(':*')) {
          const prefix = permission.slice(0, -2);
          return required.startsWith(prefix + ':');
        }
        return false;
      });
    });
  }

  /**
   * RSA キーペアを生成
   */
  static generateKeyPair(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    return { publicKey, privateKey };
  }

  /**
   * RSA 署名を生成
   */
  static signWithRSA(data: string, privateKey: string): string {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(privateKey, 'base64');
  }

  /**
   * RSA 署名を検証
   */
  static verifyRSASignature(
    data: string,
    signature: string,
    publicKey: string
  ): boolean {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(data);
      return verify.verify(publicKey, signature, 'base64');
    } catch (error) {
      return false;
    }
  }

  /**
   * 有効期限文字列をパース (例: "1h", "30m", "7d")
   */
  private static parseExpirationTime(expiration: string): number {
    const match = expiration.match(/^(\d+)([smhd])$/);
    if (!match) throw new Error(`Invalid expiration format: ${expiration}`);

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 60 * 60 * 24;
      default: throw new Error(`Unknown time unit: ${unit}`);
    }
  }

  /**
   * セキュアなランダム文字列を生成
   */
  static generateSecureRandom(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * ハッシュ化
   */
  static hash(data: string, algorithm: string = 'sha256'): string {
    return crypto.createHash(algorithm).update(data).digest('hex');
  }

  /**
   * レート制限キーを生成
   */
  static generateRateLimitKey(serviceId: string, endpoint: string): string {
    return `rate_limit:${serviceId}:${endpoint}`;
  }
}

