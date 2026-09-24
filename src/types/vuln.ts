export interface CVEItem {
  id: string;
  source: 'NVD (NIST)' | 'OSV.dev' | 'Threat Intel Knowledge Base';
  cvssScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  publishedDate?: string;
  references?: string[];
  cwe?: string[];
}

export interface ScanResult {
  target: string;
  parsedName: string;
  parsedVersion: string;
  scanTimestamp: string;
  executionTimeMs: number;
  overallSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  maxCvssScore: number;
  totalVulnerabilities: number;
  cves: CVEItem[];
  markdownReport: string;
  sourcesStatus: {
    nvd: { status: 'success' | 'warning' | 'error'; message: string; count: number };
    osv: { status: 'success' | 'warning' | 'error'; message: string; count: number };
  };
  rawResponses: {
    nvd?: any;
    osv?: any;
  };
}

export interface PresetTarget {
  name: string;
  category: string;
  query: string;
  description: string;
  badge: 'CRÍTICO' | 'ALTO' | 'MEDIO';
}
