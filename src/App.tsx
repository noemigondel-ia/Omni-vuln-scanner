/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { SearchPanel } from './components/SearchPanel';
import { ScanProgress } from './components/ScanProgress';
import { ReportViewer } from './components/ReportViewer';
import { CveMatrix } from './components/CveMatrix';
import { OsintTelemetry } from './components/OsintTelemetry';
import { HistoryModal } from './components/HistoryModal';
import { SeverityAnalytics } from './components/SeverityAnalytics';
import { ScanResult } from './types/vuln';
import { 
  getLocalAuditHistory, 
  saveAuditToHistory, 
  deleteAuditFromHistory, 
  clearAllAuditHistory,
  HistoryItem
} from './utils/historyStorage';
import { 
  ShieldAlert, 
  FileText, 
  Layers, 
  Database, 
  AlertTriangle, 
  CheckCircle, 
  Info,
  Terminal,
  Server,
  Lock,
  Cpu,
  History,
  Zap,
  BarChart3
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'report' | 'analytics' | 'cves' | 'telemetry'>('report');
  const [currentQuery, setCurrentQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  
  // Local storage history state
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState<boolean>(false);
  const [loadedFromHistoryNotice, setLoadedFromHistoryNotice] = useState<string | null>(null);

  // Load history on initial mount
  useEffect(() => {
    const saved = getLocalAuditHistory();
    setHistory(saved);
  }, []);

  const handleStartScan = async (query: string) => {
    if (!query.trim()) return;

    setCurrentQuery(query);
    setIsLoading(true);
    setErrorMessage(null);
    setLoadedFromHistoryNotice(null);

    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ techInput: query }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Error del servidor (HTTP ${response.status})`);
      }

      const data: ScanResult = await response.json();
      setScanResult(data);
      setActiveTab('report');

      // Persist to local storage history
      const updatedHistory = saveAuditToHistory(data);
      setHistory(updatedHistory);
    } catch (err: any) {
      console.error('Scan error:', err);
      setErrorMessage(
        err.message || 'Error inesperado durante la auditoría OSINT. Por favor, intenta de nuevo.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Select an audit from history without re-calling APIs
  const handleSelectAuditFromHistory = (cachedAudit: ScanResult) => {
    setScanResult(cachedAudit);
    setCurrentQuery(cachedAudit.target);
    setErrorMessage(null);
    setActiveTab('report');
    setLoadedFromHistoryNotice(
      `Cargado instantáneamente desde el historial local (Fecha original: ${new Date(
        cachedAudit.scanTimestamp
      ).toLocaleString()}) sin reconsultar APIs.`
    );
    // Auto-dismiss notice after 5 seconds
    setTimeout(() => {
      setLoadedFromHistoryNotice(null);
    }, 5000);
  };

  const handleDeleteHistoryItem = (id: string) => {
    const updated = deleteAuditFromHistory(id);
    setHistory(updated);
  };

  const handleClearAllHistory = () => {
    clearAllAuditHistory();
    setHistory([]);
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans soc-grid-bg relative">
      {/* Background cyber glow gradients */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-900/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-blue-900/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main SOC Header */}
      <Header 
        historyCount={history.length}
        onOpenHistory={() => setIsHistoryModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Search & Vector Input Panel with quick history access */}
        <SearchPanel 
          onScan={handleStartScan} 
          isLoading={isLoading} 
          history={history}
          onOpenHistory={() => setIsHistoryModalOpen(true)}
          onSelectAuditFromHistory={handleSelectAuditFromHistory}
        />

        {/* Local Storage Loaded Notification banner */}
        {loadedFromHistoryNotice && (
          <div className="p-3.5 rounded-xl bg-cyan-950/80 border border-cyan-700/70 text-cyan-300 flex items-center justify-between gap-3 shadow-lg font-mono text-xs animate-fadeIn">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400 shrink-0 animate-pulse" />
              <span>{loadedFromHistoryNotice}</span>
            </div>
            <button
              type="button"
              onClick={() => setLoadedFromHistoryNotice(null)}
              className="text-cyan-400 hover:text-cyan-200 text-xs px-2 py-0.5 rounded hover:bg-cyan-900/40"
            >
              Cerrar
            </button>
          </div>
        )}

        {/* Error notification */}
        {errorMessage && (
          <div className="p-4 rounded-xl bg-red-950/80 border border-red-800 text-red-300 flex items-start gap-3 shadow-lg font-mono text-xs">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-red-200">FALLO EN AUDITORÍA OSINT:</span>
              <p className="mt-0.5">{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Loading / Scan In Progress Skeleton */}
        {isLoading && (
          <ScanProgress target={currentQuery} />
        )}

        {/* Results Area */}
        {!isLoading && scanResult && (
          <div className="space-y-5">
            {/* Always visible Top Analytics Bar (Recharts) for fast analytical glance */}
            <SeverityAnalytics scanResult={scanResult} />

            {/* Tab Navigation */}
            <div className="flex items-center justify-between border-b border-cyan-950/80 pb-2 no-print">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setActiveTab('report')}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-mono text-xs font-semibold transition-all ${
                    activeTab === 'report'
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/80 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <FileText className="w-4 h-4" />
                  <span>Informe Blue Team (IA)</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('cves')}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-mono text-xs font-semibold transition-all ${
                    activeTab === 'cves'
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/80 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <Layers className="w-4 h-4" />
                  <span>Matriz de CVEs ({scanResult.cves.length})</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('telemetry')}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-mono text-xs font-semibold transition-all ${
                    activeTab === 'telemetry'
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/80 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <Database className="w-4 h-4" />
                  <span>Telemetría OSINT & Raw APIs</span>
                </button>
              </div>

              {/* Target & History Indicator */}
              <div className="hidden sm:flex items-center gap-3 text-xs font-mono text-slate-400">
                <button
                  type="button"
                  onClick={() => setIsHistoryModalOpen(true)}
                  className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                >
                  <History className="w-3.5 h-3.5" />
                  <span>Historial ({history.length})</span>
                </button>
                <span>|</span>
                <div>
                  <span>Objetivo:</span>{' '}
                  <span className="font-bold text-cyan-300">{scanResult.target}</span>
                </div>
              </div>
            </div>

            {/* Tab Views */}
            {activeTab === 'report' && <ReportViewer scanResult={scanResult} />}
            {activeTab === 'cves' && <CveMatrix cves={scanResult.cves} target={scanResult.target} />}
            {activeTab === 'telemetry' && <OsintTelemetry scanResult={scanResult} />}
          </div>
        )}

        {/* Initial Welcome & SOC Overview when no scan is active */}
        {!isLoading && !scanResult && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-6">
              <div className="bg-slate-900/60 border border-slate-800/90 rounded-xl p-5 shadow-lg flex flex-col justify-between">
                <div>
                  <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 mb-3">
                    <Database className="w-5 h-5" />
                  </div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 uppercase tracking-wider mb-1.5">
                    1. Extracción OSINT Multifuente
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Consulta asíncrona directa a los repositorios oficiales de <strong>NVD (NIST) API 2.0</strong> y <strong>OSV.dev</strong> para recuperar CVEs publicados, métricas CVSS v3.1 y clasificadores CWE.
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800/60 font-mono text-[11px] text-cyan-400">
                  ✓ Conexión en tiempo real
                </div>
              </div>

              <div className="bg-slate-900/60 border border-slate-800/90 rounded-xl p-5 shadow-lg flex flex-col justify-between">
                <div>
                  <div className="w-9 h-9 rounded-lg bg-indigo-950/80 border border-indigo-800/60 flex items-center justify-center text-indigo-400 mb-3">
                    <Cpu className="w-5 h-5" />
                  </div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 uppercase tracking-wider mb-1.5">
                    2. Análisis Blue Team con IA
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Procesamiento mediante <strong>Gemini Flash</strong> configurado con directivas de analista senior defensivo: resumen ejecutivo para gerencia, causas raíz técnicas, vectores de explotación y mitigación.
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800/60 font-mono text-[11px] text-indigo-400">
                  ✓ Correlación heurística
                </div>
              </div>

              <div className="bg-slate-900/60 border border-slate-800/90 rounded-xl p-5 shadow-lg flex flex-col justify-between">
                <div>
                  <div className="w-9 h-9 rounded-lg bg-emerald-950/80 border border-emerald-800/60 flex items-center justify-center text-emerald-400 mb-3">
                    <Lock className="w-5 h-5" />
                  </div>
                  <h3 className="font-mono text-sm font-bold text-slate-100 uppercase tracking-wider mb-1.5">
                    3. Memoria Local & Exportación
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Historial persistente en <strong>localStorage</strong> para revisar auditorías sin volver a llamar a las APIs, exportación lista a <strong>PDF de alta resolución</strong> y analítica visual con Recharts.
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800/60 font-mono text-[11px] text-emerald-400">
                  ✓ Acceso instantáneo offline
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* History Modal Dialog */}
      <HistoryModal
        isOpen={isHistoryModalOpen}
        onClose={() => setIsHistoryModalOpen(false)}
        history={history}
        onSelectAudit={handleSelectAuditFromHistory}
        onDeleteAudit={handleDeleteHistoryItem}
        onClearAll={handleClearAllHistory}
      />

      {/* SOC Footer */}
      <footer className="border-t border-slate-900 bg-[#050811] py-4 mt-8 no-print">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-slate-500">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>Omni-Vuln Scanner OSINT Threat Intelligence • Blue Team Defense</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsHistoryModalOpen(true)}
              className="text-cyan-400 hover:text-cyan-300 underline"
            >
              Historial ({history.length})
            </button>
            <span>•</span>
            <span>Fuentes: NIST NVD 2.0 • OSV • Gemini GenAI</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
