import { LogEntry, TimeSet } from '../core/sets';
import { LocalizationMapping } from '../core/mappings';
import { LevelDBAdapter } from '../storage/leveldb-adapter';
import { v4 as uuidv4 } from 'uuid';

export interface LogEvent {
  userId: string;
  eventType: string;
  ipAddress: string;
  countryCode: string;
  data: Record<string, unknown>;
}

export class LogGenerator {
  constructor(private storage: LevelDBAdapter) {}
  
  // f: E → L (イベントからログへの写像)
  async generateLog(event: LogEvent): Promise<LogEntry> {
    const log: LogEntry = {
      id: uuidv4(),
      timestamp: TimeSet.now(),
      userId: event.userId,
      eventType: event.eventType,
      ipAddress: event.ipAddress,
      countryCode: event.countryCode,
      data: event.data
    };
    
    // データセンター決定
    const dataCenter = LocalizationMapping.getDataCenter(log.countryCode);
    
    // ストレージに保存
    await this.storage.store(log, dataCenter);
    
    return log;
  }
  
  // バッチ生成対応
  async generateBatch(events: LogEvent[]): Promise<LogEntry[]> {
    const logs: LogEntry[] = [];
    
    for (const event of events) {
      const log = await this.generateLog(event);
      logs.push(log);
    }
    
    return logs;
  }
}

