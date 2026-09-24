import React, { useEffect, useState } from 'react';
import { ShieldAlert, Radio, Database, Cpu, Activity, Clock, History } from 'lucide-react';

interface HeaderProps {
  historyCount: number;
  onOpenHistory: () => void;
}

export const Header: React.FC<HeaderProps> = ({ historyCount, onOpenHistory }) => {
  const [time, setTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="border-b border-cyan-950/60 bg-[#070b14]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          {/* Logo & Branding */}
          <div className="flex items-center space-x-3">
            <div className="relative flex items-center justify-center w-11 h-11 rounded-lg bg-gradient-to-br from-cyan-950 via-slate-900 to-blue-950 border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <ShieldAlert className="w-6 h-6 text-cyan-400" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-cyan-300 via-sky-100 to-indigo-300 bg-clip-text text-transparent">
                  Omni-Vuln Scanner
                </h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 font-semibold tracking-wider">
                  OSINT v2.5
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-cyan-400 animate-pulse" />
                Security Operations Center (SOC) Threat Intelligence & Blue Team Audit
              </p>
            </div>
          </div>

          {/* SOC Status Badges & Quick History */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <button
              type="button"
              onClick={onOpenHistory}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 hover:bg-cyan-950/60 border border-cyan-900/60 hover:border-cyan-500/60 text-cyan-300 shadow-inner transition-all"
              title="Abrir historial de auditorías guardadas localmente"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              <span>Historial:</span>
              <span className="text-cyan-300 font-bold">{historyCount}</span>
            </button>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 border border-slate-800 text-slate-300 shadow-inner">
              <Radio className="w-3.5 h-3.5 text-emerald-400" />
              <span>NVD NIST:</span>
              <span className="text-emerald-400 font-semibold">ACTIVE</span>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 border border-slate-800 text-slate-300 shadow-inner">
              <Database className="w-3.5 h-3.5 text-cyan-400" />
              <span>OSV.dev:</span>
              <span className="text-cyan-400 font-semibold">SYNCED</span>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/90 border border-slate-800 text-slate-300 shadow-inner">
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span>AI Engine:</span>
              <span className="text-indigo-300 font-semibold">Gemini Flash</span>
            </div>

            <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900/60 border border-slate-800/80 text-slate-400">
              <Clock className="w-3 h-3 text-slate-500" />
              <span className="text-[11px]">{time || '00:00:00 UTC'}</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
