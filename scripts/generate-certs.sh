#!/bin/bash

# 証明書生成スクリプト
# mTLS認証用の証明書を生成します

set -e

CERTS_DIR="./certs"
COUNTRY="JP"
STATE="Tokyo"
CITY="Tokyo"
ORGANIZATION="Hono LevelDB Logger"
ORGANIZATIONAL_UNIT="IT Department"
EMAIL="admin@example.com"

# 証明書ディレクトリを作成
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "🔐 証明書を生成しています..."

# 1. CA（認証局）の秘密鍵を生成
echo "📋 CA秘密鍵を生成中..."
openssl genrsa -out ca.key 4096

# 2. CA証明書を生成
echo "📋 CA証明書を生成中..."
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT CA/CN=Hono Logger CA/emailAddress=$EMAIL"

# 3. サーバー秘密鍵を生成
echo "📋 サーバー秘密鍵を生成中..."
openssl genrsa -out server.key 4096

# 4. サーバー証明書署名要求（CSR）を生成
echo "📋 サーバーCSRを生成中..."
openssl req -new -key server.key -out server.csr -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=localhost/emailAddress=$EMAIL"

# 5. サーバー証明書を生成（CAで署名）
echo "📋 サーバー証明書を生成中..."
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 6. クライアント秘密鍵を生成
echo "📋 クライアント秘密鍵を生成中..."
openssl genrsa -out client.key 4096

# 7. クライアント証明書署名要求（CSR）を生成
echo "📋 クライアントCSRを生成中..."
openssl req -new -key client.key -out client.csr -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=hono-client/emailAddress=$EMAIL"

# 8. クライアント証明書を生成（CAで署名）
echo "📋 クライアント証明書を生成中..."
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

# 9. 管理者クライアント証明書を生成
echo "📋 管理者クライアント証明書を生成中..."
openssl genrsa -out admin-client.key 4096
openssl req -new -key admin-client.key -out admin-client.csr -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=admin-service/emailAddress=$EMAIL"
openssl x509 -req -days 365 -in admin-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out admin-client.crt

# 10. テスト用サービス証明書を生成
echo "📋 テスト用サービス証明書を生成中..."
openssl genrsa -out test-service.key 4096
openssl req -new -key test-service.key -out test-service.csr -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=test-service/emailAddress=$EMAIL"
openssl x509 -req -days 365 -in test-service.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out test-service.crt

# 11. 証明書の検証
echo "📋 証明書を検証中..."
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt
openssl verify -CAfile ca.crt admin-client.crt
openssl verify -CAfile ca.crt test-service.crt

# 12. 証明書情報の表示
echo "📋 生成された証明書:"
echo "  - CA証明書: ca.crt"
echo "  - サーバー証明書: server.crt"
echo "  - クライアント証明書: client.crt"
echo "  - 管理者クライアント証明書: admin-client.crt"
echo "  - テスト用サービス証明書: test-service.crt"

# 13. 権限設定
chmod 600 *.key
chmod 644 *.crt

# 14. CSRファイルを削除
rm -f *.csr

echo "✅ 証明書の生成が完了しました！"
echo ""
echo "🔧 使用方法:"
echo "  1. Docker Composeでサービスを起動: docker-compose up -d"
echo "  2. mTLS接続テスト: curl --cert client.crt --key client.key --cacert ca.crt https://localhost:443/health"
echo "  3. 管理者API接続: curl --cert admin-client.crt --key admin-client.key --cacert ca.crt https://localhost:443/admin/services"
echo ""
echo "⚠️  本番環境では、より強力なパスワードと適切な証明書管理を行ってください。"

