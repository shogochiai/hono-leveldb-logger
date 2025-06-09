import { LogEntry } from '../core/sets';
import { DeletionMapping } from '../core/mappings';
import { LevelDBAdapter } from '../storage/leveldb-adapter';

export class DeletionManager {
  constructor(private storage: LevelDBAdapter) {}
  
  // δ(l_i, t) = 1 iff t > d_e(l_i)
  async deleteExpiredLogs(): Promise<number> {
    let deletedCount = 0;
    const currentTime = Date.now();
    const dataCenters = ['tokyo-dc1', 'virginia-dc1', 'frankfurt-dc1'];
    
    for (const dc of dataCenters) {
      const logs = await this.storage.query({ dataCenter: dc });
      
      for (const log of logs) {
        if (DeletionMapping.isDeletable(log, currentTime)) {
          await this.storage.delete(log.id, dc);
          deletedCount++;
          
          // 削除監査ログの生成
          await this.createDeletionAuditLog(log);
        }
      }
    }
    
    return deletedCount;
  }
  
  // スケジュール削除の設定
  scheduleAutoDeletion(intervalHours: number = 24): void {
    setInterval(async () => {
      try {
        const deleted = await this.deleteExpiredLogs();
        console.log(`Auto-deletion completed: ${deleted} logs deleted`);
      } catch (error) {
        console.error('Auto-deletion failed:', error);
      }
    }, intervalHours * 60 * 60 * 1000);
  }
  
  private async createDeletionAuditLog(deletedLog: LogEntry): Promise<void> {
    // 削除の監査証跡を残す（メタデータのみ）
    const auditLog = {
      deletedLogId: deletedLog.id,
      deletionTime: Date.now(),
      originalCreationTime: deletedLog.timestamp,
      retentionPeriod: DeletionMapping.getDeletionTime(deletedLog) - deletedLog.timestamp,
      reason: 'retention_period_expired'
    };
    
    // 監査ログは別途保存
    console.log('Deletion audit:', auditLog);
  }
}

