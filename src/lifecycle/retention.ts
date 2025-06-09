import { LogEntry, TimeSet } from '../core/sets';
import { DeletionMapping } from '../core/mappings';
import { LevelDBAdapter } from '../storage/leveldb-adapter';

export class RetentionManager {
  constructor(private storage: LevelDBAdapter) {}
  
  // S(t) = { l_i ∈ L | g(l_i) + s(l_i) >= t }
  async getRetainedLogs(
    currentTime: number,
    dataCenter: string
  ): Promise<LogEntry[]> {
    const allLogs = await this.storage.query({ dataCenter });
    
    return allLogs.filter(log => 
      !DeletionMapping.isDeletable(log, currentTime)
    );
  }
  
  // 保存状態の監視
  async monitorRetention(): Promise<{
    total: number;
    retained: number;
    deletable: number;
    byCountry: Record<string, number>;
  }> {
    const stats = {
      total: 0,
      retained: 0,
      deletable: 0,
      byCountry: {} as Record<string, number>
    };
    
    const currentTime = TimeSet.now();
    let dataCenters = ['tokyo-dc1', 'virginia-dc1', 'frankfurt-dc1'];
    
    // テスト環境の場合
    if (process.env.NODE_ENV === 'test') {
      dataCenters = ['test-dc'];
    }
    
    for (const dc of dataCenters) {
      const logs = await this.storage.query({ dataCenter: dc });
      
      for (const log of logs) {
        stats.total++;
        
        if (DeletionMapping.isDeletable(log, currentTime)) {
          stats.deletable++;
        } else {
          stats.retained++;
        }
        
        stats.byCountry[log.countryCode] = 
          (stats.byCountry[log.countryCode] || 0) + 1;
      }
    }
    
    return stats;
  }
}

