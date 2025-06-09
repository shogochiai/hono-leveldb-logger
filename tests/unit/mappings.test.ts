import { describe, it, expect } from 'vitest';
import { RetentionMapping, DeletionMapping } from '../../src/core/mappings';
import { LogEntry } from '../../src/core/sets';

describe('RetentionMapping', () => {
  it('should return maximum retention period', () => {
    const log: LogEntry = {
      id: 'test-1',
      timestamp: Date.now(),
      userId: 'user-1',
      eventType: 'login',
      ipAddress: '192.168.1.1',
      countryCode: 'JP',
      data: {}
    };
    
    const retention = RetentionMapping.getRetentionPeriod(log);
    expect(retention).toBe(10); // APPI: 10年
  });
  
  it('should handle EU regulations', () => {
    const log: LogEntry = {
      id: 'test-2',
      timestamp: Date.now(),
      userId: 'user-2',
      eventType: 'payment',
      ipAddress: '192.168.1.2',
      countryCode: 'DE',
      data: {}
    };
    
    const retention = RetentionMapping.getRetentionPeriod(log);
    expect(retention).toBe(3); // PCI-DSS: 3年（GDPRの1年より長い）
  });
  
  it('should handle unknown countries with minimum retention', () => {
    const log: LogEntry = {
      id: 'test-3',
      timestamp: Date.now(),
      userId: 'user-3',
      eventType: 'access',
      ipAddress: '192.168.1.3',
      countryCode: 'XX',
      data: {}
    };
    
    const retention = RetentionMapping.getRetentionPeriod(log);
    expect(retention).toBe(3); // PCI-DSS: 3年（ALLに適用）
  });
});

describe('DeletionMapping', () => {
  it('should calculate deletion time correctly', () => {
    const now = Date.now();
    const log: LogEntry = {
      id: 'test-4',
      timestamp: now,
      userId: 'user-4',
      eventType: 'access',
      ipAddress: '192.168.1.4',
      countryCode: 'US',
      data: {}
    };
    
    const deletionTime = DeletionMapping.getDeletionTime(log);
    const threeYearsInMillis = 3 * 365 * 24 * 60 * 60 * 1000; // PCI-DSS: 3年
    
    expect(deletionTime).toBe(now + threeYearsInMillis);
  });
  
  it('should determine if log is deletable', () => {
    const pastTime = Date.now() - (4 * 365 * 24 * 60 * 60 * 1000); // 4年前
    const log: LogEntry = {
      id: 'test-5',
      timestamp: pastTime,
      userId: 'user-5',
      eventType: 'access',
      ipAddress: '192.168.1.5',
      countryCode: 'US',
      data: {}
    };
    
    const isDeletable = DeletionMapping.isDeletable(log, Date.now());
    expect(isDeletable).toBe(true); // 4年前なので削除可能（PCI-DSS: 3年）
  });
  
  it('should not delete recent logs', () => {
    const recentTime = Date.now() - (6 * 30 * 24 * 60 * 60 * 1000); // 6ヶ月前
    const log: LogEntry = {
      id: 'test-6',
      timestamp: recentTime,
      userId: 'user-6',
      eventType: 'access',
      ipAddress: '192.168.1.6',
      countryCode: 'US',
      data: {}
    };
    
    const isDeletable = DeletionMapping.isDeletable(log, Date.now());
    expect(isDeletable).toBe(false);
  });
});

