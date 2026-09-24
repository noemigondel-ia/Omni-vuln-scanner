import { ScanResult } from '../types/vuln';

const LOCAL_STORAGE_KEY = 'omni_vuln_audit_history_v1';
const MAX_HISTORY_ITEMS = 20;

export interface HistoryItem {
  id: string;
  target: string;
  timestamp: string;
  overallSeverity: ScanResult['overallSeverity'];
  maxCvssScore: number;
  totalVulnerabilities: number;
  data: ScanResult;
}

export function getLocalAuditHistory(): HistoryItem[] {
  try {
    const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch (err) {
    console.warn('Failed to read audit history from localStorage:', err);
    return [];
  }
}

export function saveAuditToHistory(result: ScanResult): HistoryItem[] {
  try {
    const current = getLocalAuditHistory();
    // Filter out duplicate target if it already exists so the newest is at the top
    const filtered = current.filter(
      (item) => item.target.toLowerCase().trim() !== result.target.toLowerCase().trim()
    );

    const newItem: HistoryItem = {
      id: `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      target: result.target,
      timestamp: result.scanTimestamp || new Date().toISOString(),
      overallSeverity: result.overallSeverity,
      maxCvssScore: result.maxCvssScore,
      totalVulnerabilities: result.totalVulnerabilities,
      data: result,
    };

    const updated = [newItem, ...filtered].slice(0, MAX_HISTORY_ITEMS);
    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.warn('Failed to save audit to localStorage:', err);
    return getLocalAuditHistory();
  }
}

export function deleteAuditFromHistory(id: string): HistoryItem[] {
  try {
    const current = getLocalAuditHistory();
    const updated = current.filter((item) => item.id !== id);
    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.warn('Failed to delete audit from localStorage:', err);
    return getLocalAuditHistory();
  }
}

export function clearAllAuditHistory(): void {
  try {
    localStorage.removeItem(LOCAL_STORAGE_KEY);
  } catch (err) {
    console.warn('Failed to clear audit history from localStorage:', err);
  }
}
