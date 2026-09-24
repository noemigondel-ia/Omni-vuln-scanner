import React, { useMemo, useState } from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  Legend 
} from 'recharts';
import { ShieldAlert, BarChart3, PieChart as PieIcon, Activity, AlertTriangle, ShieldCheck } from 'lucide-react';
import { ScanResult } from '../types/vuln';

interface SeverityAnalyticsProps {
  scanResult: ScanResult;
}

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string; border: string }> = {
  CRITICAL: {
    label: 'Crítico',
    color: '#f43f5e', // rose-500
    bg: 'bg-rose-950/60',
    border: 'border-rose-700/60',
  },
  HIGH: {
    label: 'Alto',
    color: '#f97316', // orange-500
    bg: 'bg-amber-950/60',
    border: 'border-amber-700/60',
  },
  MEDIUM: {
    label: 'Medio',
    color: '#eab308', // yellow-500
    bg: 'bg-yellow-950/60',
    border: 'border-yellow-700/60',
  },
  LOW: {
    label: 'Bajo',
    color: '#06b6d4', // cyan-500
    bg: 'bg-cyan-950/60',
    border: 'border-cyan-800/60',
  },
};

export const SeverityAnalytics: React.FC<SeverityAnalyticsProps> = ({ scanResult }) => {
  const [chartType, setChartType] = useState<'donut' | 'bar'>('donut');

  const { distribution, total, cvssAverage, maxScore } = useMemo(() => {
    const counts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    let totalScore = 0;
    let countedScores = 0;
    let max = 0;

    scanResult.cves.forEach((c) => {
      const sev = c.severity in counts ? (c.severity as keyof typeof counts) : 'MEDIUM';
      counts[sev] += 1;

      if (c.cvssScore > 0) {
        totalScore += c.cvssScore;
        countedScores += 1;
        if (c.cvssScore > max) max = c.cvssScore;
      }
    });

    // If no individual CVEs were recorded but overall is defined
    const totalCount = scanResult.cves.length;
    if (totalCount === 0) {
      const sev = scanResult.overallSeverity in counts ? (scanResult.overallSeverity as keyof typeof counts) : 'HIGH';
      counts[sev] = 1;
      max = scanResult.maxCvssScore || 7.5;
    }

    const data = [
      { name: 'Crítico', key: 'CRITICAL', value: counts.CRITICAL, color: SEVERITY_CONFIG.CRITICAL.color },
      { name: 'Alto', key: 'HIGH', value: counts.HIGH, color: SEVERITY_CONFIG.HIGH.color },
      { name: 'Medio', key: 'MEDIUM', value: counts.MEDIUM, color: SEVERITY_CONFIG.MEDIUM.color },
      { name: 'Bajo', key: 'LOW', value: counts.LOW, color: SEVERITY_CONFIG.LOW.color },
    ].filter((item) => item.value > 0);

    const avg = countedScores > 0 ? (totalScore / countedScores).toFixed(1) : (scanResult.maxCvssScore || 0).toFixed(1);

    return {
      distribution: data,
      total: totalCount || 1,
      cvssAverage: avg,
      maxScore: max > 0 ? max.toFixed(1) : scanResult.maxCvssScore.toFixed(1),
    };
  }, [scanResult]);

  // Custom tooltip for SOC dark mode
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      const percentage = ((data.value / total) * 100).toFixed(1);
      return (
        <div className="bg-slate-950/95 border border-cyan-700/60 p-2.5 rounded-lg shadow-xl font-mono text-xs">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.payload.color }} />
            <span className="font-bold text-slate-100">{data.name}</span>
          </div>
          <div className="text-slate-300">
            Cantidad: <strong className="text-cyan-300">{data.value}</strong> ({percentage}%)
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-slate-900/90 border border-cyan-900/50 rounded-xl p-5 shadow-2xl backdrop-blur-md">
      {/* Top Header & Chart Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
              Perfil de Riesgo y Distribución de Severidad
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-normal">
                {scanResult.totalVulnerabilities} CVEs catalogados
              </span>
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Resumen analítico con Recharts del impacto de seguridad detectado en {scanResult.target}
            </p>
          </div>
        </div>

        {/* Toggle between Donut / Bar chart */}
        <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-1 text-xs font-mono shrink-0">
          <button
            type="button"
            onClick={() => setChartType('donut')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all ${
              chartType === 'donut'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <PieIcon className="w-3.5 h-3.5" />
            <span>Pastel / Anillo</span>
          </button>

          <button
            type="button"
            onClick={() => setChartType('bar')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all ${
              chartType === 'bar'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 shadow-sm font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            <span>Barras</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Visual Chart + Metrics Counters */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mt-4 items-center">
        {/* Recharts Component Container */}
        <div className="lg:col-span-7 h-64 sm:h-72 w-full flex items-center justify-center relative">
          <ResponsiveContainer width="100%" height="100%">
            {chartType === 'donut' ? (
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                  stroke="#080d19"
                  strokeWidth={2}
                >
                  {distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend 
                  wrapperStyle={{ fontFamily: 'monospace', fontSize: '11px', paddingTop: '10px' }}
                  formatter={(value) => <span className="text-slate-300">{value}</span>}
                />
              </PieChart>
            ) : (
              <BarChart data={distribution} margin={{ top: 20, right: 20, left: -10, bottom: 5 }}>
                <XAxis 
                  dataKey="name" 
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }} 
                  axisLine={{ stroke: '#334155' }}
                />
                <YAxis 
                  allowDecimals={false}
                  tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }} 
                  axisLine={{ stroke: '#334155' }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {distribution.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            )}
          </ResponsiveContainer>

          {/* Center text for donut */}
          {chartType === 'donut' && (
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pb-6">
              <span className="text-[10px] uppercase font-mono tracking-widest text-slate-400">Total</span>
              <span className="text-xl font-bold font-mono text-cyan-300">{total}</span>
              <span className="text-[9px] font-mono text-slate-500">CVEs</span>
            </div>
          )}
        </div>

        {/* Severity Metrics & KPIs */}
        <div className="lg:col-span-5 space-y-3 font-mono">
          <div className="grid grid-cols-2 gap-2.5">
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase">Puntuación CVSS Máxima</span>
              <span className="text-lg font-bold text-rose-400 flex items-center gap-1.5 mt-0.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                {maxScore} <span className="text-xs text-slate-500 font-normal">/ 10.0</span>
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase">Promedio CVSS Base</span>
              <span className="text-lg font-bold text-amber-400 flex items-center gap-1.5 mt-0.5">
                <Activity className="w-4 h-4 text-amber-400" />
                {cvssAverage} <span className="text-xs text-slate-500 font-normal">/ 10.0</span>
              </span>
            </div>
          </div>

          {/* Breakdown Pills */}
          <div className="space-y-1.5 pt-1">
            {Object.entries(SEVERITY_CONFIG).map(([key, config]) => {
              const item = distribution.find((d) => d.key === key);
              const count = item ? item.value : 0;
              const pct = total > 0 ? ((count / total) * 100).toFixed(0) : '0';

              return (
                <div
                  key={key}
                  className="flex items-center justify-between p-2 rounded-lg bg-slate-950/50 border border-slate-800/80 text-xs"
                >
                  <div className="flex items-center gap-2">
                    <span 
                      className="w-2.5 h-2.5 rounded-sm" 
                      style={{ backgroundColor: config.color }} 
                    />
                    <span className="text-slate-300 font-semibold">{config.label}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-[11px]">{pct}%</span>
                    <span 
                      className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                        count > 0 ? config.bg + ' ' + config.border + ' border' : 'text-slate-600'
                      }`}
                      style={{ color: count > 0 ? config.color : undefined }}
                    >
                      {count} {count === 1 ? 'CVE' : 'CVEs'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
