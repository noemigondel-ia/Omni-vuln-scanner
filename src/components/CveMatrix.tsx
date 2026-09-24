import React, { useState } from 'react';
import { ShieldAlert, ExternalLink, Filter, Search, Tag, Calendar, Database } from 'lucide-react';
import { CVEItem } from '../types/vuln';

interface CveMatrixProps {
  cves: CVEItem[];
  target: string;
}

export const CveMatrix: React.FC<CveMatrixProps> = ({ cves, target }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filtered = cves.filter((c) => {
    const matchesSev = filterSeverity === 'ALL' || c.severity === filterSeverity;
    const matchesSearch =
      c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c.cwe || []).some((w) => w.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSev && matchesSearch;
  });

  const getCvssBadge = (score: number, severity: CVEItem['severity']) => {
    if (score >= 9.0 || severity === 'CRITICAL') {
      return 'bg-rose-950/80 text-rose-400 border-rose-700/60 shadow-[0_0_10px_rgba(244,63,94,0.2)]';
    }
    if (score >= 7.0 || severity === 'HIGH') {
      return 'bg-amber-950/80 text-amber-400 border-amber-700/60 shadow-[0_0_10px_rgba(245,158,11,0.2)]';
    }
    if (score >= 4.0 || severity === 'MEDIUM') {
      return 'bg-yellow-950/80 text-yellow-300 border-yellow-700/60';
    }
    return 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60';
  };

  return (
    <div className="space-y-4">
      {/* Controls & Filter Bar */}
      <div className="bg-slate-900/90 border border-cyan-900/40 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xl backdrop-blur-md">
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="font-mono text-xs text-slate-300 uppercase tracking-wider font-semibold">
            Filtro de Severidad:
          </span>
          <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-1 text-xs font-mono">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-1 rounded transition-all ${
                  filterSeverity === sev
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev === 'ALL' ? 'TODOS' : sev}
              </button>
            ))}
          </div>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar CVE o palabra clave..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* CVEs Cards / Table */}
      {filtered.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center">
          <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h4 className="text-base font-mono font-semibold text-slate-300">
            No se encontraron registros con los filtros seleccionados
          </h4>
          <p className="text-xs text-slate-500 font-mono mt-1">
            Prueba ajustando el filtro de severidad o el término de búsqueda.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((cve, cveIndex) => {
            const isNist = cve.id.startsWith('CVE-');
            const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cve.id}`;
            const mitreUrl = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`;
            // Ensure unique weakness list per CVE
            const uniqueCwes = Array.from(new Set(cve.cwe || []));

            return (
              <div
                key={`${cve.id}-${cve.source}-${cveIndex}`}
                className="bg-slate-900/80 border border-slate-800 hover:border-cyan-500/40 rounded-xl p-5 shadow-lg transition-all"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                  <div className="flex items-center gap-3">
                    <span className="text-base font-mono font-bold text-cyan-300 tracking-wide">
                      {cve.id}
                    </span>

                    <span
                      className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${getCvssBadge(
                        cve.cvssScore,
                        cve.severity
                      )}`}
                    >
                      {cve.severity} • CVSS {cve.cvssScore > 0 ? cve.cvssScore : 'N/A'}
                    </span>

                    <span className="flex items-center gap-1 text-[11px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      <Database className="w-3 h-3 text-cyan-400" />
                      {cve.source}
                    </span>
                  </div>

                  {/* External Links */}
                  <div className="flex items-center gap-2">
                    {isNist && (
                      <>
                        <a
                          href={nvdUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-xs font-mono px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-cyan-400 hover:text-cyan-300 border border-slate-800 transition-all"
                        >
                          <span>NVD NIST</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                        <a
                          href={mitreUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-xs font-mono px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-sky-400 hover:text-sky-300 border border-slate-800 transition-all"
                        >
                          <span>MITRE</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </>
                    )}
                  </div>
                </div>

                {/* Summary */}
                <p className="text-sm text-slate-300 leading-relaxed mt-3">
                  {cve.summary}
                </p>

                {/* Metadata tags: CWE, Published */}
                <div className="flex flex-wrap items-center gap-2 mt-4 pt-3 border-t border-slate-800/60 text-xs font-mono text-slate-400">
                  {cve.publishedDate && (
                    <div className="flex items-center gap-1 text-slate-400">
                      <Calendar className="w-3.5 h-3.5 text-slate-500" />
                      <span>Publicado: {new Date(cve.publishedDate).toLocaleDateString()}</span>
                    </div>
                  )}

                  {uniqueCwes.length > 0 && (
                    <div className="flex items-center gap-1.5 ml-auto flex-wrap">
                      <Tag className="w-3 h-3 text-cyan-400" />
                      {uniqueCwes.map((weakness, weaknessIdx) => (
                        <span
                          key={`${cve.id}-${weakness}-${weaknessIdx}`}
                          className="px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-slate-800 text-[11px]"
                        >
                          {weakness}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
