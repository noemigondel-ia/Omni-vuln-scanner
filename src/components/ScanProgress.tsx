import React, { useEffect, useState } from 'react';
import { Shield, Database, Cpu, Activity, CheckCircle2 } from 'lucide-react';

interface ScanProgressProps {
  target: string;
}

const STEPS = [
  { id: 1, label: 'Iniciando conexión segura con NIST NVD API 2.0 (cves/2.0)...', icon: Database },
  { id: 2, label: 'Consultando base de vulnerabilidades Open Source OSV.dev...', icon: Shield },
  { id: 3, label: 'Correlacionando puntuaciones CVSS v3.1, vectores CWE y debilidades...', icon: Activity },
  { id: 4, label: 'Sintetizando informe de auditoría Blue Team con Gemini 3.8 Flash...', icon: Cpu },
];

export const ScanProgress: React.FC<ScanProgressProps> = ({ target }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < STEPS.length - 1 ? prev + 1 : prev));
    }, 1200);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-slate-900/90 border border-cyan-900/50 rounded-xl p-6 shadow-2xl backdrop-blur-md animate-fadeIn">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-500/50">
            <Activity className="w-5 h-5 text-cyan-400 animate-spin" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-cyan-400 font-bold uppercase tracking-wider">
                Auditoría OSINT en Curso
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-300 border border-cyan-700/40">
                LIVE SOC FEED
              </span>
            </div>
            <p className="font-mono text-sm text-slate-200 mt-0.5">
              Vector objetivo: <span className="text-cyan-300 font-bold">"{target}"</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="inline-flex h-2.5 w-2.5 rounded-full bg-cyan-400 animate-ping" />
          <span className="font-mono text-xs text-cyan-300">Consultando fuentes públicas...</span>
        </div>
      </div>

      {/* Terminal log steps */}
      <div className="py-5 space-y-3 font-mono text-xs">
        {STEPS.map((step, idx) => {
          const Icon = step.icon;
          const isDone = idx < currentStepIndex;
          const isCurrent = idx === currentStepIndex;
          return (
            <div
              key={step.id}
              className={`flex items-center gap-3 p-2.5 rounded-lg border transition-all ${
                isCurrent
                  ? 'bg-cyan-950/40 border-cyan-500/40 text-cyan-200'
                  : isDone
                  ? 'bg-slate-950/40 border-slate-800 text-slate-400'
                  : 'bg-transparent border-transparent text-slate-600 opacity-50'
              }`}
            >
              <div className="shrink-0">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : isCurrent ? (
                  <Icon className="w-4 h-4 text-cyan-400 animate-bounce" />
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-700" />
                )}
              </div>
              <span className="flex-1">{step.label}</span>
              {isCurrent && (
                <span className="text-[10px] px-1.5 py-0.5 bg-cyan-500/20 text-cyan-300 rounded animate-pulse">
                  PROCESANDO
                </span>
              )}
              {isDone && <span className="text-[10px] text-emerald-400">OK</span>}
            </div>
          );
        })}
      </div>

      {/* Report Skeleton Simulation */}
      <div className="pt-4 border-t border-slate-800 space-y-4">
        <div className="flex items-center gap-2">
          <div className="h-4 w-32 bg-slate-800 rounded animate-pulse" />
          <div className="h-4 w-16 bg-slate-800/60 rounded animate-pulse" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="h-20 bg-slate-800/40 border border-slate-800/60 rounded-lg p-3 space-y-2 animate-pulse">
            <div className="h-3 w-20 bg-slate-700/60 rounded" />
            <div className="h-6 w-16 bg-slate-700/80 rounded" />
          </div>
          <div className="h-20 bg-slate-800/40 border border-slate-800/60 rounded-lg p-3 space-y-2 animate-pulse">
            <div className="h-3 w-24 bg-slate-700/60 rounded" />
            <div className="h-6 w-20 bg-slate-700/80 rounded" />
          </div>
          <div className="h-20 bg-slate-800/40 border border-slate-800/60 rounded-lg p-3 space-y-2 animate-pulse">
            <div className="h-3 w-28 bg-slate-700/60 rounded" />
            <div className="h-6 w-24 bg-slate-700/80 rounded" />
          </div>
        </div>

        <div className="space-y-2 pt-2">
          <div className="h-3.5 bg-slate-800/50 rounded w-full animate-pulse" />
          <div className="h-3.5 bg-slate-800/40 rounded w-11/12 animate-pulse" />
          <div className="h-3.5 bg-slate-800/30 rounded w-4/5 animate-pulse" />
          <div className="h-24 bg-slate-950 border border-slate-800/80 rounded-lg p-3 animate-pulse mt-3" />
        </div>
      </div>
    </div>
  );
};
