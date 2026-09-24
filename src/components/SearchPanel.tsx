import React, { useState } from 'react';
import { Search, Sparkles, Terminal, AlertTriangle, ShieldCheck, History, Zap } from 'lucide-react';
import { PresetTarget, ScanResult } from '../types/vuln';
import { HistoryItem } from '../utils/historyStorage';

interface SearchPanelProps {
  onScan: (query: string) => void;
  isLoading: boolean;
  history: HistoryItem[];
  onOpenHistory: () => void;
  onSelectAuditFromHistory: (audit: ScanResult) => void;
}

const PRESETS: PresetTarget[] = [
  {
    name: 'Apache HTTP',
    category: 'Web Server',
    query: 'apache 2.4.49',
    description: 'Path Traversal & RCE crítico (CVE-2021-41773)',
    badge: 'CRÍTICO',
  },
  {
    name: 'Log4j',
    category: 'Java Library',
    query: 'log4j 2.14.0',
    description: 'Log4Shell JNDI Inyección RCE (CVE-2021-44228)',
    badge: 'CRÍTICO',
  },
  {
    name: 'OpenSSL',
    category: 'Criptografía',
    query: 'openssl 3.0.0',
    description: 'Desbordamiento de búfer X.509 (CVE-2022-3602)',
    badge: 'ALTO',
  },
  {
    name: 'Spring Framework',
    category: 'Framework Java',
    query: 'spring-framework 5.3.18',
    description: 'Spring4Shell DataBinder RCE (CVE-2022-22965)',
    badge: 'CRÍTICO',
  },
  {
    name: 'Nginx',
    category: 'Web Server',
    query: 'nginx 1.20.0',
    description: 'Corrupción de memoria en módulo MP4 (CVE-2021-23017)',
    badge: 'ALTO',
  },
  {
    name: 'WordPress',
    category: 'CMS Core',
    query: 'wordpress 5.8',
    description: 'Inyecciones SQL y SSRF en plugins y core',
    badge: 'MEDIO',
  },
];

export const SearchPanel: React.FC<SearchPanelProps> = ({ 
  onScan, 
  isLoading,
  history,
  onOpenHistory,
  onSelectAuditFromHistory
}) => {
  const [inputVal, setInputVal] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputVal.trim() && !isLoading) {
      onScan(inputVal.trim());
    }
  };

  const handleSelectPreset = (query: string) => {
    setInputVal(query);
    onScan(query);
  };

  return (
    <div className="relative bg-slate-900/80 border border-cyan-900/40 rounded-xl p-5 md:p-6 shadow-2xl backdrop-blur-md overflow-hidden">
      {/* Decorative top accent glow */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500 to-transparent opacity-80" />

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-100 uppercase tracking-wider font-mono">
            Módulo de Entrada OSINT & Vector Tecnológico
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onOpenHistory}
            className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-slate-950 border border-cyan-800/60 hover:border-cyan-500/80 text-cyan-300 hover:text-cyan-200 text-xs font-mono transition-all shadow-sm active:scale-95"
            title="Ver auditorías previas guardadas en localStorage"
          >
            <History className="w-3.5 h-3.5 text-cyan-400" />
            <span>Historial Local</span>
            {history.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-cyan-900 text-cyan-200 text-[10px] font-bold">
                {history.length}
              </span>
            )}
          </button>

          <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block animate-ping" />
            <span>NVD NIST • OSV.dev • Blue Team</span>
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-slate-400" />
            </div>
            <input
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              placeholder="Nombre de la tecnología y versión (Ej. apache 2.4.49, log4j 2.14.0)"
              disabled={isLoading}
              className="w-full pl-11 pr-4 py-3.5 bg-[#080d19] border border-cyan-900/50 rounded-lg text-slate-100 placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all shadow-inner disabled:opacity-50"
            />
            {inputVal && (
              <button
                type="button"
                onClick={() => setInputVal('')}
                className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-xs text-slate-500 hover:text-slate-300 font-mono"
              >
                Limpiar
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={isLoading || !inputVal.trim()}
            className="flex items-center justify-center gap-2 px-7 py-3.5 bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:via-sky-500 hover:to-blue-500 active:from-cyan-700 active:to-blue-700 text-white font-mono font-medium text-sm rounded-lg shadow-[0_0_20px_rgba(6,182,212,0.3)] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none shrink-0"
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Escaneando OSINT...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-cyan-200" />
                <span>Iniciar Auditoría OSINT</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Quick History Bar if items exist */}
      {history.length > 0 && (
        <div className="mt-4 pt-3.5 border-t border-slate-800/60">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5 uppercase tracking-wider">
              <History className="w-3.5 h-3.5 text-cyan-400" />
              Auditorías Recientes en Memoria Local (Acceso Instantáneo):
            </span>
            <button
              type="button"
              onClick={onOpenHistory}
              className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
            >
              Ver todas ({history.length}) →
            </button>
          </div>

          <div className="flex items-center gap-2 overflow-x-auto pb-1.5 scrollbar-thin">
            {history.slice(0, 5).map((h) => (
              <button
                key={h.id}
                type="button"
                onClick={() => onSelectAuditFromHistory(h.data)}
                disabled={isLoading}
                className="group flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-cyan-500/60 hover:bg-slate-900 text-xs font-mono transition-all shrink-0 active:scale-95"
                title={`Cargar ${h.target} analizado el ${new Date(h.timestamp).toLocaleTimeString()}`}
              >
                <Zap className="w-3 h-3 text-cyan-400 group-hover:animate-pulse" />
                <span className="font-bold text-slate-200 group-hover:text-cyan-300">
                  {h.target}
                </span>
                <span
                  className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                    h.overallSeverity === 'CRITICAL'
                      ? 'bg-red-950 text-red-400 border border-red-800/60'
                      : h.overallSeverity === 'HIGH'
                      ? 'bg-amber-950 text-amber-400 border border-amber-800/60'
                      : 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                  }`}
                >
                  {h.overallSeverity}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Quick Preset Badges */}
      <div className="mt-4 pt-3.5 border-t border-slate-800/80">
        <div className="flex items-center justify-between gap-2 mb-2.5">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            Vectores de Auditoría Rápidos (Casos Notorios):
          </span>
          <span className="text-[11px] text-slate-500 font-mono hidden sm:inline">
            Haz clic para cargar y ejecutar
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {PRESETS.map((preset) => (
            <button
              key={preset.query}
              type="button"
              onClick={() => handleSelectPreset(preset.query)}
              disabled={isLoading}
              className="flex flex-col items-start text-left p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/90 hover:border-cyan-500/50 hover:bg-slate-800/60 transition-all group disabled:opacity-50"
            >
              <div className="flex items-center justify-between w-full mb-1">
                <span className="font-mono text-xs font-bold text-slate-200 group-hover:text-cyan-300 truncate">
                  {preset.name}
                </span>
                <span
                  className={`text-[9px] px-1 py-0.2 rounded font-mono font-bold ${
                    preset.badge === 'CRÍTICO'
                      ? 'bg-rose-950/80 text-rose-400 border border-rose-800/50'
                      : preset.badge === 'ALTO'
                      ? 'bg-amber-950/80 text-amber-400 border border-amber-800/50'
                      : 'bg-yellow-950/80 text-yellow-400 border border-yellow-800/50'
                  }`}
                >
                  {preset.badge}
                </span>
              </div>
              <span className="font-mono text-[11px] text-cyan-400/80 truncate w-full mb-0.5">
                {preset.query}
              </span>
              <span className="text-[10px] text-slate-400 line-clamp-1 leading-tight">
                {preset.description}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
