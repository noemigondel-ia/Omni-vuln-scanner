import React from 'react';
import { History, Clock, Trash2, ShieldAlert, ArrowRight, Database, X, Zap } from 'lucide-react';
import { HistoryItem } from '../utils/historyStorage';
import { ScanResult } from '../types/vuln';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  history: HistoryItem[];
  onSelectAudit: (audit: ScanResult) => void;
  onDeleteAudit: (id: string) => void;
  onClearAll: () => void;
}

export const HistoryModal: React.FC<HistoryModalProps> = ({
  isOpen,
  onClose,
  history,
  onSelectAudit,
  onDeleteAudit,
  onClearAll,
}) => {
  if (!isOpen) return null;

  const getSeverityBadge = (severity: HistoryItem['overallSeverity']) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-700/60 shadow-[0_0_8px_rgba(239,68,68,0.25)]';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-400 border-amber-700/60';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-700/60';
      case 'LOW':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div 
        className="relative w-full max-w-2xl max-h-[85vh] flex flex-col bg-[#0b1120] border border-cyan-900/60 rounded-xl shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-cyan-950/80 bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
              <History className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                Historial de Auditorías Locales
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-normal">
                  {history.length} guardadas
                </span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Carga inmediata desde memoria local sin reconsultar APIs ni gastar cuota
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content list */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
          {history.length === 0 ? (
            <div className="py-12 text-center">
              <History className="w-12 h-12 text-slate-700 mx-auto mb-3" />
              <p className="font-mono text-sm text-slate-400 font-semibold">
                No hay auditorías guardadas en el historial local
              </p>
              <p className="font-mono text-xs text-slate-500 mt-1">
                Realiza una auditoría de tecnología y se almacenará automáticamente aquí.
              </p>
            </div>
          ) : (
            history.map((item) => (
              <div
                key={item.id}
                className="group flex flex-col sm:flex-row sm:items-center justify-between p-3.5 rounded-lg bg-slate-900/70 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-all gap-3"
              >
                <div 
                  className="flex-1 cursor-pointer"
                  onClick={() => {
                    onSelectAudit(item.data);
                    onClose();
                  }}
                >
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-sm font-bold text-cyan-300 group-hover:text-cyan-200">
                      {item.target}
                    </span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold border ${getSeverityBadge(
                        item.overallSeverity
                      )}`}
                    >
                      {item.overallSeverity} (CVSS {item.maxCvssScore})
                    </span>
                    <span className="text-[11px] font-mono text-slate-500">
                      • {item.totalVulnerabilities} CVEs
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      {new Date(item.timestamp).toLocaleString()}
                    </span>
                    <span className="hidden sm:inline text-cyan-400/80 flex items-center gap-1">
                      <Zap className="w-3 h-3" /> Acceso instantáneo
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                  <button
                    onClick={() => {
                      onSelectAudit(item.data);
                      onClose();
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/80 font-mono text-xs transition-all active:scale-95"
                    title="Cargar auditoría guardada"
                  >
                    <span>Cargar</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onDeleteAudit(item.id);
                    }}
                    className="p-1.5 rounded-md text-slate-500 hover:text-red-400 hover:bg-red-950/40 border border-transparent hover:border-red-900/60 transition-colors"
                    title="Eliminar del historial"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        {history.length > 0 && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-slate-800/80 bg-slate-950/80 text-xs font-mono">
            <span className="text-slate-500">
              Almacenado localmente en tu navegador (localStorage)
            </span>
            <button
              onClick={() => {
                if (confirm('¿Estás seguro de que deseas vaciar todo el historial local?')) {
                  onClearAll();
                }
              }}
              className="flex items-center gap-1 text-slate-400 hover:text-red-400 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Vaciar Historial</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
