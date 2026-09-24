import React, { useState } from 'react';
import { Database, Radio, CheckCircle, AlertCircle, Copy, Check, Terminal, ExternalLink } from 'lucide-react';
import { ScanResult } from '../types/vuln';

interface OsintTelemetryProps {
  scanResult: ScanResult;
}

export const OsintTelemetry: React.FC<OsintTelemetryProps> = ({ scanResult }) => {
  const [copiedNvd, setCopiedNvd] = useState(false);
  const [copiedOsv, setCopiedOsv] = useState(false);

  const copyJson = async (data: any, type: 'nvd' | 'osv') => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
      if (type === 'nvd') {
        setCopiedNvd(true);
        setTimeout(() => setCopiedNvd(false), 2000);
      } else {
        setCopiedOsv(true);
        setTimeout(() => setCopiedOsv(false), 2000);
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Sources Health Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* NVD Card */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Radio className="w-5 h-5 text-emerald-400" />
              <div>
                <h4 className="font-mono text-sm font-bold text-slate-100">
                  NVD NIST 2.0 (National Vulnerability Database)
                </h4>
                <span className="text-[11px] font-mono text-slate-400">
                  Endpoint: services.nvd.nist.gov/rest/json/cves/2.0
                </span>
              </div>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 font-mono text-xs">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>{scanResult.sourcesStatus.nvd.status.toUpperCase()}</span>
            </div>
          </div>

          <p className="text-xs font-mono text-slate-300 mt-3">
            {scanResult.sourcesStatus.nvd.message}
          </p>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Registros extraídos: <strong>{scanResult.sourcesStatus.nvd.count}</strong></span>
            <button
              onClick={() => copyJson(scanResult.rawResponses.nvd, 'nvd')}
              className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              {copiedNvd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedNvd ? 'Copiado JSON' : 'Copiar Raw NVD'}</span>
            </button>
          </div>
        </div>

        {/* OSV.dev Card */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Database className="w-5 h-5 text-cyan-400" />
              <div>
                <h4 className="font-mono text-sm font-bold text-slate-100">
                  OSV.dev (Open Source Vulnerability Feed)
                </h4>
                <span className="text-[11px] font-mono text-slate-400">
                  Endpoint: api.osv.dev/v1/query
                </span>
              </div>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300 font-mono text-xs">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>{scanResult.sourcesStatus.osv.status.toUpperCase()}</span>
            </div>
          </div>

          <p className="text-xs font-mono text-slate-300 mt-3">
            {scanResult.sourcesStatus.osv.message}
          </p>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Registros extraídos: <strong>{scanResult.sourcesStatus.osv.count}</strong></span>
            <button
              onClick={() => copyJson(scanResult.rawResponses.osv, 'osv')}
              className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              {copiedOsv ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedOsv ? 'Copiado JSON' : 'Copiar Raw OSV'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Raw Payload Inspector */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2 font-mono text-sm text-slate-200">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-bold">Inspector de Telemetría JSON (NVD NIST API Response)</span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            Solo lectura para auditoría
          </span>
        </div>

        <div className="mt-4 relative max-h-96 overflow-y-auto rounded-lg bg-slate-950 border border-slate-800/80 p-4">
          <pre className="text-xs font-mono text-emerald-400/90 leading-relaxed whitespace-pre-wrap">
            {JSON.stringify(scanResult.rawResponses.nvd || { notice: 'No raw payload' }, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
};
