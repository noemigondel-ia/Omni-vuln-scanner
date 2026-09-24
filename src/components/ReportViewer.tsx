import React, { useMemo, useState, useRef } from 'react';
import { marked } from 'marked';
import { 
  FileDown, 
  Copy, 
  Check, 
  ShieldAlert, 
  Printer, 
  FileText,
  Wrench,
  Loader2,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { ScanResult } from '../types/vuln';
import { generateReportPdf } from '../utils/pdfExport';

interface ReportViewerProps {
  scanResult: ScanResult;
}

export const ReportViewer: React.FC<ReportViewerProps> = ({ scanResult }) => {
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<'rendered' | 'raw'>('rendered');
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfSuccess, setPdfSuccess] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);

  const reportContainerRef = useRef<HTMLDivElement>(null);

  // Copy report to clipboard
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(scanResult.markdownReport);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch (err) {
      console.error('Failed to copy markdown:', err);
    }
  };

  // Enhance markdown HTML with SOC-themed color tags for criticality
  const renderedHtml = useMemo(() => {
    try {
      marked.setOptions({
        gfm: true,
        breaks: true,
      });
      let html = marked.parse(scanResult.markdownReport) as string;

      // Colorize criticality labels
      // Crítico (Red)
      html = html.replace(
        /\[CRÍTICO\]|\[CRITICAL\]|\b(CRÍTICO|CRITICAL)\b/g,
        (match) => `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-red-950/90 text-red-400 border border-red-700/60 shadow-[0_0_8px_rgba(239,68,68,0.3)]">${match}</span>`
      );

      // Alto (Orange)
      html = html.replace(
        /\[ALTO\]|\[HIGH\]|\b(ALTO|HIGH)\b(?!\s*score|\s*puntu)/g,
        (match) => `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-950/90 text-amber-400 border border-amber-700/60 shadow-[0_0_8px_rgba(245,158,11,0.25)]">${match}</span>`
      );

      // Medio (Yellow)
      html = html.replace(
        /\[MEDIO\]|\[MEDIUM\]|\b(MEDIO|MEDIUM)\b/g,
        (match) => `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-yellow-950/90 text-yellow-300 border border-yellow-700/60">${match}</span>`
      );

      // Bajo (Green/Cyan)
      html = html.replace(
        /\[BAJO\]|\[LOW\]|\b(BAJO|LOW)\b/g,
        (match) => `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950/90 text-cyan-300 border border-cyan-800/60">${match}</span>`
      );

      // Style CVE tags nicely
      html = html.replace(
        /\b(CVE-\d{4}-\d{4,7})\b/g,
        '<a href="https://nvd.nist.gov/vuln/detail/$1" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-2 decoration-cyan-500/50 hover:decoration-cyan-400 font-semibold">$1 ↗</a>'
      );

      return html;
    } catch (e) {
      return scanResult.markdownReport;
    }
  }, [scanResult.markdownReport]);

  // Robust Client-side PDF Generation with clean print CSS styling
  const handleExportPdf = async () => {
    if (isGeneratingPdf) return;

    try {
      setIsGeneratingPdf(true);
      setPdfError(null);

      // Trigger robust client-side PDF generation respecting .print-clean styling
      await generateReportPdf({
        scanResult,
        htmlContent: renderedHtml,
      });

      setPdfSuccess(true);
      setTimeout(() => setPdfSuccess(false), 3500);
    } catch (error: any) {
      console.error('Error generando PDF con html2canvas y jsPDF:', error);
      setPdfError(error?.message || 'Error al procesar el PDF');

      // Seamless fallback to browser print dialog
      try {
        window.print();
      } catch (printErr) {
        console.error('Print fallback failed:', printErr);
      }
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Direct print alternative
  const handlePrint = () => {
    try {
      window.print();
    } catch (e) {
      console.error('Window print error:', e);
    }
  };

  const severityColor = {
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.25)]',
    HIGH: 'bg-amber-500/20 text-amber-400 border-amber-500/50 shadow-[0_0_15px_rgba(245,158,11,0.25)]',
    MEDIUM: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50',
    LOW: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50',
    INFO: 'bg-slate-500/20 text-slate-300 border-slate-500/50',
  }[scanResult.overallSeverity];

  return (
    <div className="space-y-4">
      {/* Top Action Bar & Threat Level Header */}
      <div className="bg-slate-900/90 border border-cyan-900/40 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl backdrop-blur-md no-print">
        {/* Severity & Target Overview */}
        <div className="flex items-center gap-4">
          <div className={`flex flex-col items-center justify-center px-4 py-2 rounded-lg border font-mono ${severityColor}`}>
            <span className="text-[10px] uppercase font-bold tracking-widest text-slate-400">Riesgo Global</span>
            <span className="text-lg font-extrabold tracking-wider">{scanResult.overallSeverity}</span>
            <span className="text-[11px] font-semibold">CVSS {scanResult.maxCvssScore} / 10</span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-bold text-slate-100 font-mono">
                Informe de Auditoría OSINT & Blue Team
              </h3>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                {scanResult.target}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Generado: {new Date(scanResult.scanTimestamp).toLocaleString()} • Latencia de correlación: {scanResult.executionTimeMs}ms
            </p>
          </div>
        </div>

        {/* Buttons: Copy & Export to PDF */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-1 mr-1 text-xs font-mono">
            <button
              onClick={() => setViewMode('rendered')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                viewMode === 'rendered'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Vista Formateada
            </button>
            <button
              onClick={() => setViewMode('raw')}
              className={`px-3 py-1.5 rounded-md transition-all ${
                viewMode === 'raw'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Markdown Crudo
            </button>
          </div>

          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-mono text-xs transition-all active:scale-95"
            title="Copiar informe completo en formato Markdown"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-semibold">¡Copiado!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span>Copiar</span>
              </>
            )}
          </button>

          {/* Primary Robust Client-side PDF Generation Button */}
          <button
            type="button"
            onClick={handleExportPdf}
            disabled={isGeneratingPdf}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:via-sky-500 hover:to-blue-500 text-white font-mono text-xs font-medium shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all active:scale-95 disabled:opacity-60"
            title="Generar y descargar documento PDF formateado con html2canvas y jsPDF"
          >
            {isGeneratingPdf ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Generando PDF...</span>
              </>
            ) : pdfSuccess ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-300" />
                <span className="text-emerald-200 font-bold">¡PDF Descargado!</span>
              </>
            ) : (
              <>
                <FileDown className="w-3.5 h-3.5" />
                <span>Exportar Informe a PDF</span>
              </>
            )}
          </button>

          {/* Secondary system print dialog button */}
          <button
            type="button"
            onClick={handlePrint}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-all"
            title="Imprimir documento mediante el diálogo del navegador"
          >
            <Printer className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error notification if PDF generation had issues */}
      {pdfError && (
        <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>Error generando PDF: {pdfError}. Se abrió el cuadro de impresión como alternativa.</span>
        </div>
      )}

      {/* Report Content Body in Dark SOC Theme */}
      <div 
        ref={reportContainerRef}
        className="bg-slate-900/80 border border-cyan-950/60 rounded-xl p-6 md:p-8 shadow-2xl backdrop-blur-md print-clean"
      >
        <div className="mb-4 pb-3 border-b border-cyan-950/80 flex items-center justify-between text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-cyan-300">OMNI-VULN SCANNER OSINT REPORT</span>
          </div>
          <div>
            <span>Objetivo: <strong className="text-slate-200">{scanResult.target}</strong></span>
          </div>
        </div>

        {viewMode === 'raw' ? (
          <div className="relative">
            <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {scanResult.markdownReport}
            </pre>
          </div>
        ) : (
          <div 
            className="prose prose-invert max-w-none 
              prose-headings:font-mono prose-headings:text-slate-100 prose-headings:tracking-wide
              prose-h1:text-xl prose-h1:text-cyan-300 prose-h1:border-b prose-h1:border-cyan-900/60 prose-h1:pb-2 prose-h1:mt-2
              prose-h2:text-lg prose-h2:text-sky-200 prose-h2:border-b prose-h2:border-slate-800 prose-h2:pb-1.5 prose-h2:mt-6
              prose-h3:text-base prose-h3:text-slate-200 prose-h3:mt-4
              prose-p:text-slate-300 prose-p:leading-relaxed prose-p:text-sm
              prose-li:text-slate-300 prose-li:text-sm prose-li:leading-relaxed
              prose-strong:text-cyan-200 prose-strong:font-bold
              prose-code:font-mono prose-code:text-cyan-300 prose-code:bg-slate-950 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:border prose-code:border-slate-800
              prose-pre:bg-[#070b14] prose-pre:border prose-pre:border-cyan-950 prose-pre:text-slate-200 prose-pre:p-4 prose-pre:rounded-lg
              prose-table:border-collapse prose-table:w-full prose-table:my-4 prose-table:text-sm
              prose-th:border prose-th:border-slate-800 prose-th:bg-slate-950/80 prose-th:p-2.5 prose-th:text-cyan-300 prose-th:font-mono prose-th:text-xs
              prose-td:border prose-td:border-slate-800/80 prose-td:p-2.5 prose-td:text-slate-300 prose-td:text-xs
              prose-blockquote:border-l-4 prose-blockquote:border-cyan-500 prose-blockquote:bg-cyan-950/20 prose-blockquote:px-4 prose-blockquote:py-1 prose-blockquote:rounded-r prose-blockquote:text-slate-300
            "
            dangerouslySetInnerHTML={{ __html: renderedHtml }}
          />
        )}
      </div>

      {/* Blue Team Remediation Quick Bar */}
      <div className="bg-gradient-to-r from-cyan-950/40 via-slate-900/80 to-blue-950/40 border border-cyan-800/30 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono no-print">
        <div className="flex items-center gap-2 text-cyan-300">
          <Wrench className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>Para aplicar contramedidas operativas, revisa los parches y reglas de WAF en la sección <strong>Plan de Remediación</strong>.</span>
        </div>
        <button
          onClick={handleExportPdf}
          disabled={isGeneratingPdf}
          className="text-cyan-400 hover:text-cyan-300 underline underline-offset-4 shrink-0 font-semibold flex items-center gap-1.5"
        >
          {isGeneratingPdf ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}
          <span>Exportar Documento Oficial (PDF) →</span>
        </button>
      </div>
    </div>
  );
};
