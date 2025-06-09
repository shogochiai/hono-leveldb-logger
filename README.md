# hono-leveldb-logger

包括的ログ設計ライブラリ with マイクロサービス認証機構

[![CI](https://github.com/your-username/hono-leveldb-logger/workflows/CI/badge.svg)](https://github.com/your-username/hono-leveldb-logger/actions)
[![npm version](https://badge.fury.io/js/hono-leveldb-logger.svg)](https://badge.fury.io/js/hono-leveldb-logger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 概要

hono-leveldb-loggerは、グローバル規制対応とマイクロサービス間認証を統合した包括的なログ管理ライブラリです。GDPR、APPI、PCI-DSSなどの規制に自動対応し、高性能なLevelDBストレージと強固な認証機構を提供します。

## ✨ 主な機能

### 📊 ログ管理
- **高性能ストレージ**: LevelDBベースの高速データ保存
- **AES-256-GCM暗号化**: 保存時データの完全暗号化
- **自動削除機能**: 規制に基づく保存期間管理
- **データローカリゼーション**: 国別データセンター対応

### 🔐 認証機構
- **mTLS（Mutual TLS）**: 最高レベルのトランスポート層認証
- **JWT Service Token**: 標準的なアプリケーション層認証
- **API Key + HMAC**: 軽量で高速な認証オプション
- **リプレイ攻撃防止**: Nonceとタイムスタンプ検証

### 🌍 規制対応
- **GDPR**: EU一般データ保護規則対応
- **APPI**: 日本個人情報保護法対応
- **PCI-DSS**: 決済カード業界データセキュリティ基準対応
- **自動保存期間管理**: 規制に基づく自動データ削除

### 🏗️ アーキテクチャ
- **マイクロサービス対応**: サービス間認証とログ追跡
- **高可用性**: Redis、Consul連携による冗長性
- **監視・メトリクス**: Prometheus、Grafana統合
- **Docker対応**: 完全なコンテナ化環境

## 📦 インストール

```bash
npm install hono-leveldb-logger
```

## 🚀 クイックスタート

### 基本的な使用方法

```typescript
import { startServer, getDefaultAuthConfig } from 'hono-leveldb-logger';

// サーバーを起動
const { app, storage, authConfig } = await startServer(3000);

console.log('🚀 Hono LevelDB Logger started on port 3000');
```

### クライアントライブラリの使用

```typescript
import { LogServiceClient } from 'hono-leveldb-logger';

// JWT認証でクライアントを作成
const client = new LogServiceClient({
  serviceCredentials: {
    serviceId: 'user-service',
    serviceName: 'User Service',
    privateKey: '...',
    permissions: ['logs:read', 'logs:write']
  },
  targetUrl: 'https://logging-service:3443',
  authMethod: 'jwt'
});

// ログを送信
await client.log({
  userId: 'user-123',
  eventType: 'user.login',
  data: { ip: '192.168.1.1', source: 'web' }
});
```

### API Key認証

```typescript
// API Key認証でクライアントを作成
const client = new LogServiceClient({
  serviceCredentials: {
    serviceId: 'payment-service',
    serviceName: 'Payment Service',
    apiKey: 'your-api-key',
    permissions: ['logs:write']
  },
  targetUrl: 'https://logging-service:3000',
  authMethod: 'api_key'
});

// ログを送信
await client.log({
  userId: 'user-456',
  eventType: 'payment.completed',
  data: { amount: 1000, currency: 'JPY' }
});
```

## 🔧 設定

### 環境変数

```bash
# 基本設定
NODE_ENV=production
PORT=3000
HTTPS_PORT=3443

# 暗号化設定
ENCRYPTION_KEY=your-64-character-hex-encryption-key

# JWT設定
JWT_SECRET=your-jwt-secret
JWT_ISSUER=hono-leveldb-logger
JWT_AUDIENCE=hono-leveldb-logger

# API Key設定
API_KEY_SECRET=your-api-key-secret

# mTLS設定
ENABLE_MTLS=true
TLS_CERT_PATH=/app/certs/server.crt
TLS_KEY_PATH=/app/certs/server.key
TLS_CA_PATH=/app/certs/ca.crt
```

### Docker Compose

```bash
# 環境設定をコピー
cp .env.example .env

# 証明書を生成
./scripts/generate-certs.sh

# サービスを起動
docker-compose up -d
```

## 🔐 認証方式

### 1. mTLS認証（推奨）

最も安全な認証方式。クライアント証明書による相互認証。

```bash
# 証明書を使用してAPIにアクセス
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:443/api/logs \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-123","eventType":"test","data":{}}'
```

### 2. JWT認証

標準的なトークンベース認証。

```bash
# JWTトークンを使用
curl -H "Authorization: Bearer $JWT_TOKEN" \
  https://localhost:3000/api/logs \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-123","eventType":"test","data":{}}'
```

### 3. API Key認証

軽量で高速な署名ベース認証。

```bash
# API Keyと署名を使用
curl -H "X-API-Key: $API_KEY" \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Nonce: $NONCE" \
  https://localhost:3000/api/logs \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-123","eventType":"test","data":{}}'
```

## 📊 API エンドポイント

### ログ管理

```
POST   /api/logs              # ログ作成
GET    /api/logs              # ログ検索
GET    /api/logs/:id          # ログ取得
DELETE /api/logs/:id          # ログ削除（規制対応）
```

### 認証管理

```
POST   /admin/services        # サービス登録
GET    /admin/services        # サービス一覧
POST   /admin/services/:id/rotate  # 認証情報ローテーション
GET    /api/auth/test         # 認証テスト
```

### システム

```
GET    /health                # ヘルスチェック
GET    /metrics               # Prometheusメトリクス
GET    /version               # バージョン情報
```

## 🧪 テスト

```bash
# 全テストを実行
npm test

# カバレッジ付きテスト
npm run test:coverage

# 認証テストのみ
npm test -- tests/auth/

# 統合テストのみ
npm test -- tests/integration/
```

## 📈 監視とメトリクス

### Prometheus メトリクス

- `hono_logger_requests_total`: リクエスト総数
- `hono_logger_request_duration_seconds`: リクエスト処理時間
- `hono_logger_auth_attempts_total`: 認証試行回数
- `hono_logger_logs_stored_total`: 保存ログ数
- `hono_logger_logs_deleted_total`: 削除ログ数

### Grafana ダッシュボード

Docker Composeでサービスを起動すると、Grafanaダッシュボードが自動的に設定されます：

- URL: http://localhost:3001
- ユーザー: admin
- パスワード: admin（変更推奨）

## 🔒 セキュリティ

### 暗号化

- **保存時暗号化**: AES-256-GCM
- **転送時暗号化**: TLS 1.2/1.3
- **キー管理**: 環境変数による安全な管理

### 認証セキュリティ

- **リプレイ攻撃防止**: Nonce + タイムスタンプ
- **署名検証**: HMAC-SHA256
- **証明書検証**: X.509 PKI
- **レート制限**: サービス単位での流量制御

## 🌍 規制対応詳細

### GDPR（EU一般データ保護規則）

- **データ最小化**: 必要最小限のデータのみ収集
- **保存期間制限**: 7年後の自動削除
- **削除権**: 個人データの削除API
- **データポータビリティ**: エクスポート機能

### APPI（日本個人情報保護法）

- **適正取得**: 正当な手段による取得
- **利用目的の明示**: ログ目的の明確化
- **安全管理措置**: 暗号化とアクセス制御
- **保存期間**: 7年後の自動削除

### PCI-DSS（決済カード業界基準）

- **データ保護**: カード情報の暗号化
- **アクセス制御**: 最小権限の原則
- **監視**: 全アクセスのログ記録
- **保存期間**: 3年後の自動削除

## 🏗️ アーキテクチャ

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │  Load Balancer  │    │   Hono Logger   │
│                 │────│     (Nginx)     │────│    Service      │
│ • Web App       │    │                 │    │                 │
│ • Mobile App    │    │ • Rate Limiting │    │ • Authentication│
│ • Microservices │    │ • SSL/TLS       │    │ • Log Storage   │
└─────────────────┘    └─────────────────┘    │ • Encryption    │
                                              └─────────────────┘
                                                       │
                       ┌─────────────────┐            │
                       │     Redis       │────────────┤
                       │                 │            │
                       │ • Caching       │            │
                       │ • Rate Limiting │            │
                       └─────────────────┘            │
                                                      │
                       ┌─────────────────┐            │
                       │    Consul       │────────────┤
                       │                 │            │
                       │ • Service       │            │
                       │   Discovery     │            │
                       └─────────────────┘            │
                                                      │
                       ┌─────────────────┐            │
                       │   LevelDB       │────────────┘
                       │                 │
                       │ • Log Storage   │
                       │ • Encryption    │
                       └─────────────────┘
```

## 🤝 コントリビューション

1. フォークしてください
2. フィーチャーブランチを作成してください (`git checkout -b feature/amazing-feature`)
3. 変更をコミットしてください (`git commit -m 'Add amazing feature'`)
4. ブランチにプッシュしてください (`git push origin feature/amazing-feature`)
5. プルリクエストを作成してください

## 📄 ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルをご覧ください。

## 🙏 謝辞

- [Hono](https://hono.dev/) - 高速なWebフレームワーク
- [LevelDB](https://github.com/Level/level) - 高性能キーバリューストレージ
- [Node.js](https://nodejs.org/) - JavaScript ランタイム

## 📞 サポート

- 📧 Email: support@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/hono-leveldb-logger/issues)
- 📖 Documentation: [Wiki](https://github.com/your-username/hono-leveldb-logger/wiki)

---

**⚠️ 重要**: 本番環境では必ず適切な暗号化キーとシークレットを設定してください。デフォルト値は開発用途のみです。

