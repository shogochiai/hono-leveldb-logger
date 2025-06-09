import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { LogGenerator } from '../lifecycle/generation';
import { RetentionManager } from '../lifecycle/retention';
import { DeletionManager } from '../lifecycle/deletion';
import { LevelDBAdapter } from '../storage/leveldb-adapter';
import { AuthService } from '../auth/services/auth-service';
import { AuthMiddleware, getAuthContext, getServiceId } from '../auth/middleware/auth-middleware';
import { AuthConfig, ServiceRegistration } from '../auth/types';

export function createApp(storage: LevelDBAdapter, authConfig: AuthConfig) {
  const app = new Hono();
  
  // ミドルウェア
  app.use('*', cors());
  
  // 認証サービスとミドルウェアの初期化
  const authService = new AuthService(storage, authConfig);
  const authMiddleware = new AuthMiddleware(authService);
  
  const logGenerator = new LogGenerator(storage);
  const retentionManager = new RetentionManager(storage);
  const deletionManager = new DeletionManager(storage);
  
  // パブリックエンドポイント
  app.get('/health', (c) => {
    return c.json({ 
      status: 'healthy', 
      timestamp: Date.now(),
      version: '1.0.0'
    });
  });

  // 管理者エンドポイント - サービス登録
  app.post('/admin/services', authMiddleware.requireAdmin(), async (c) => {
    try {
      const registration = await c.req.json() as Omit<ServiceRegistration, 'createdAt' | 'updatedAt'>;
      
      // バリデーション
      if (!registration.serviceId || !registration.serviceName) {
        return c.json({ error: 'serviceId and serviceName are required' }, 400);
      }

      const credentials = await authService.registerService(registration);
      
      return c.json({
        success: true,
        serviceId: credentials.serviceId,
        credentials: {
          serviceId: credentials.serviceId,
          serviceName: credentials.serviceName,
          apiKey: credentials.apiKey,
          publicKey: credentials.publicKey,
          privateKey: credentials.privateKey,
          permissions: credentials.permissions
        }
      });
    } catch (error) {
      console.error('Service registration error:', error);
      return c.json({ error: 'Failed to register service' }, 500);
    }
  });

  // 管理者エンドポイント - 認証情報ローテーション
  app.post('/admin/services/:serviceId/rotate', authMiddleware.requireAdmin(), async (c) => {
    try {
      const serviceId = c.req.param('serviceId');
      const credentials = await authService.rotateServiceCredentials(serviceId);
      
      return c.json({
        success: true,
        credentials
      });
    } catch (error) {
      console.error('Credential rotation error:', error);
      return c.json({ error: 'Failed to rotate credentials' }, 500);
    }
  });

  // 認証が必要なAPIエンドポイント
  app.use('/api/*', authMiddleware.authenticate({
    requiredPermissions: ['logs:read', 'logs:write'],
    skipPaths: ['/api/health']
  }));

  // ログ生成エンドポイント
  app.post('/api/logs', authMiddleware.requirePermissions(['logs:write']), async (c) => {
    try {
      const event = await c.req.json();
      const authContext = getAuthContext(c);
      const serviceId = getServiceId(c);
      
      // バリデーション
      if (!event.userId || !event.eventType) {
        return c.json({ error: 'userId and eventType are required' }, 400);
      }
      
      // IPアドレスとCountryCodeの自動取得
      event.ipAddress = c.req.header('x-forwarded-for') || 
                       c.req.header('x-real-ip') || 
                       c.req.header('cf-connecting-ip') || 
                       '127.0.0.1';
      event.countryCode = c.req.header('cloudflare-ipcountry') || 
                         c.req.header('cf-ipcountry') || 
                         'JP';
      
      // サービス情報を追加
      event.data = {
        ...event.data,
        _serviceId: serviceId,
        _serviceName: authContext?.serviceName,
        _authMethod: authContext?.method
      };
      
      const log = await logGenerator.generateLog(event);
      
      return c.json({ 
        success: true, 
        logId: log.id,
        timestamp: log.timestamp
      });
    } catch (error) {
      console.error('Log generation error:', error);
      return c.json({ error: 'Failed to generate log' }, 500);
    }
  });
  
  // ログ取得エンドポイント
  app.get('/api/logs/:id', authMiddleware.requirePermissions(['logs:read']), async (c) => {
    try {
      const logId = c.req.param('id');
      const dataCenter = c.req.query('dc') || 'tokyo-dc1';
      
      const log = await storage.retrieve(logId, dataCenter);
      
      if (!log) {
        return c.json({ error: 'Log not found' }, 404);
      }
      
      // サービス固有のログのみ表示（管理者は除く）
      const authContext = getAuthContext(c);
      const isAdmin = authContext?.permissions.includes('admin:*') || 
                     authContext?.permissions.includes('*');
      
      if (!isAdmin && log.data._serviceId !== getServiceId(c)) {
        return c.json({ error: 'Access denied' }, 403);
      }
      
      return c.json(log);
    } catch (error) {
      console.error('Log retrieval error:', error);
      return c.json({ error: 'Failed to retrieve log' }, 500);
    }
  });
  
  // ログ検索エンドポイント
  app.get('/api/logs', authMiddleware.requirePermissions(['logs:read']), async (c) => {
    try {
      const query: {
        dataCenter: string;
        startTime?: number;
        endTime?: number;
        userId?: string;
      } = {
        dataCenter: c.req.query('dc') || 'tokyo-dc1'
      };
      
      const startParam = c.req.query('start');
      if (startParam) {
        query.startTime = parseInt(startParam);
      }
      
      const endParam = c.req.query('end');
      if (endParam) {
        query.endTime = parseInt(endParam);
      }
      
      const userIdParam = c.req.query('userId');
      if (userIdParam) {
        query.userId = userIdParam;
      }
      
      let logs = await storage.query(query);
      
      // サービス固有のログのみフィルタ（管理者は除く）
      const authContext = getAuthContext(c);
      const isAdmin = authContext?.permissions.includes('admin:*') || 
                     authContext?.permissions.includes('*');
      
      if (!isAdmin) {
        const serviceId = getServiceId(c);
        logs = logs.filter(log => log.data._serviceId === serviceId);
      }
      
      return c.json({ 
        logs, 
        count: logs.length,
        serviceId: getServiceId(c),
        permissions: authContext?.permissions || []
      });
    } catch (error) {
      console.error('Log search error:', error);
      return c.json({ error: 'Failed to search logs' }, 500);
    }
  });
  
  // 保存統計エンドポイント
  app.get('/api/retention/stats', authMiddleware.requirePermissions(['logs:read']), async (c) => {
    try {
      const stats = await retentionManager.monitorRetention();
      
      return c.json({
        ...stats,
        serviceId: getServiceId(c),
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Retention stats error:', error);
      return c.json({ error: 'Failed to get retention stats' }, 500);
    }
  });
  
  // 手動削除エンドポイント（管理者のみ）
  app.post('/api/deletion/execute', authMiddleware.requireAdmin(), async (c) => {
    try {
      const deletedCount = await deletionManager.deleteExpiredLogs();
      
      return c.json({ 
        success: true, 
        deletedCount,
        executedBy: getServiceId(c),
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Manual deletion error:', error);
      return c.json({ error: 'Failed to execute deletion' }, 500);
    }
  });

  // 認証テストエンドポイント
  app.get('/api/auth/test', authMiddleware.authenticate(), async (c) => {
    const authContext = getAuthContext(c);
    
    return c.json({
      success: true,
      serviceId: authContext?.serviceId,
      serviceName: authContext?.serviceName,
      permissions: authContext?.permissions,
      method: authContext?.method,
      timestamp: Date.now()
    });
  });
  
  return app;
}

