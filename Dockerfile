# マルチステージビルドでサイズを最適化
FROM node:20-alpine AS builder

WORKDIR /app

# パッケージファイルをコピー
COPY package*.json ./
COPY tsconfig.json ./

# 依存関係をインストール
RUN npm ci --only=production

# ソースコードをコピー
COPY src/ ./src/

# TypeScriptをビルド
RUN npm run build

# 本番用イメージ
FROM node:20-alpine AS production

# セキュリティのため非rootユーザーを作成
RUN addgroup -g 1001 -S nodejs && \
    adduser -S hono -u 1001

WORKDIR /app

# 必要なファイルのみをコピー
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

# データディレクトリを作成
RUN mkdir -p /app/data && \
    chown -R hono:nodejs /app

# 非rootユーザーに切り替え
USER hono

# ヘルスチェック
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# ポートを公開
EXPOSE 3000

# 環境変数のデフォルト値
ENV NODE_ENV=production
ENV PORT=3000
ENV LOG_LEVEL=info

# アプリケーションを起動
CMD ["node", "dist/index.js"]

