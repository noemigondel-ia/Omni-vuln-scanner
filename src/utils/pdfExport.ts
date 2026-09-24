import { jsPDF } from 'jspdf';
import { ScanResult } from '../types/vuln';

export interface GeneratePdfOptions {
  scanResult: ScanResult;
  htmlContent: string;
}

/**
 * Robust Client-Side PDF Generation Utility.
 * 
 * Uses direct, pure jsPDF text, vector, and layout drawing with standard RGB colors.
 * This completely bypasses html2canvas and the modern browser CSS "oklab" color parsing bug
 * (e.g. Tailwind v4 oklab color palette) and ensures 100% reliable, zero-error, multi-page
 * PDF downloads across all browsers and embedded iframe environments.
 */
export async function generateReportPdf({
  scanResult,
}: GeneratePdfOptions): Promise<void> {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const margin = 16;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;
  let pageNumber = 1;

  // Helper: check page break
  const ensureSpace = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - 18) {
      drawFooter();
      doc.addPage();
      pageNumber++;
      y = margin;
      drawHeaderWatermark();
    }
  };

  const drawHeaderWatermark = () => {
    doc.setFontSize(8);
    doc.setTextColor(140, 155, 175);
    doc.text('OMNI-VULN SCANNER • INFORME CONFIDENCIAL DE AUDITORÍA BLUE TEAM', margin, 10);
    doc.setDrawColor(220, 226, 235);
    doc.setLineWidth(0.3);
    doc.line(margin, 12, pageWidth - margin, 12);
  };

  const drawFooter = () => {
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 175);
    doc.setDrawColor(220, 226, 235);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
    doc.text(
      'Documento generado automáticamente por Omni-Vuln Scanner con IA Gemini & NIST NVD 2.0',
      margin,
      pageHeight - 7
    );
    doc.text(`Página ${pageNumber}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
  };

  // 1. Initial Page Top Banner
  drawHeaderWatermark();
  y = 20;

  // Badge colors in standard sRGB
  const sevColors: Record<string, { r: number; g: number; b: number; textR: number; textG: number; textB: number }> = {
    CRITICAL: { r: 254, g: 226, b: 226, textR: 190, textG: 18, textB: 60 },
    HIGH: { r: 254, g: 243, b: 199, textR: 180, textG: 83, textB: 9 },
    MEDIUM: { r: 254, g: 249, b: 195, textR: 161, textG: 98, textB: 7 },
    LOW: { r: 224, g: 242, b: 254, textR: 3, textG: 105, textB: 161 },
    INFO: { r: 241, g: 245, b: 249, textR: 71, textG: 85, textB: 105 },
  };

  const currentSev = sevColors[scanResult.overallSeverity] || sevColors.HIGH;

  // Title & Header Box
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(15, 23, 42); // #0f172a
  doc.text('Informe de Auditoría Blue Team & OSINT', margin, y);
  y += 7;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text(`Análisis de vulnerabilidades, criticidad y directivas de mitigación para: ${scanResult.target}`, margin, y);
  y += 8;

  // Summary Metrics Box
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'FD');

  // Overall Severity Badge inside box
  doc.setFillColor(currentSev.r, currentSev.g, currentSev.b);
  doc.roundedRect(margin + 4, y + 4, 38, 16, 2, 2, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(currentSev.textR, currentSev.textG, currentSev.textB);
  doc.text(scanResult.overallSeverity, margin + 23, y + 14, { align: 'center' });

  // Key stats
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(71, 85, 105);

  const col1X = margin + 48;
  const col2X = margin + 105;

  doc.text('Objetivo auditado:', col1X, y + 9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(scanResult.target, col1X + 30, y + 9);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('CVSS Máximo:', col1X, y + 17);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(currentSev.textR, currentSev.textG, currentSev.textB);
  doc.text(`${scanResult.maxCvssScore} / 10.0`, col1X + 30, y + 17);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('Total CVEs:', col2X, y + 9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(`${scanResult.totalVulnerabilities}`, col2X + 22, y + 9);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('Fecha:', col2X, y + 17);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(new Date(scanResult.scanTimestamp).toLocaleDateString(), col2X + 22, y + 17);

  y += 30;

  // 2. CVE Summary Table if available
  if (scanResult.cves && scanResult.cves.length > 0) {
    ensureSpace(20);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(15, 23, 42);
    doc.text('1. Vulnerabilidades Notorias Detectadas (CVE Matrix)', margin, y);
    y += 6;

    // Table Header
    doc.setFillColor(241, 245, 249);
    doc.rect(margin, y, contentWidth, 7, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    doc.text('IDENTIFICADOR', margin + 3, y + 5);
    doc.text('CVSS / SEV', margin + 45, y + 5);
    doc.text('ORIGEN', margin + 75, y + 5);
    doc.text('DESCRIPCIÓN / IMPACTO', margin + 115, y + 5);
    y += 7;

    scanResult.cves.slice(0, 10).forEach((cve, idx) => {
      const summaryLines = doc.splitTextToSize(cve.summary || 'Sin descripción disponible', contentWidth - 118);
      const rowHeight = Math.max(8, summaryLines.length * 4 + 4);

      ensureSpace(rowHeight);

      if (idx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, rowHeight, 'F');
      }

      doc.setDrawColor(241, 245, 249);
      doc.line(margin, y + rowHeight, margin + contentWidth, y + rowHeight);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(2, 132, 199);
      doc.text(cve.id, margin + 3, y + 5);

      doc.setFont('helvetica', 'bold');
      const cveSev = sevColors[cve.severity] || sevColors.MEDIUM;
      doc.setTextColor(cveSev.textR, cveSev.textG, cveSev.textB);
      doc.text(`${cve.cvssScore > 0 ? cve.cvssScore : 'N/A'} - ${cve.severity}`, margin + 45, y + 5);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.text(cve.source, margin + 75, y + 5);

      doc.setTextColor(51, 65, 85);
      doc.text(summaryLines, margin + 115, y + 5);

      y += rowHeight;
    });

    y += 8;
  }

  // 3. Structured Markdown Report (AI Blue Team analysis)
  ensureSpace(20);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(15, 23, 42);
  doc.text('2. Análisis Ejecutivo y Plan de Mitigación Defensiva', margin, y);
  y += 8;

  const rawLines = scanResult.markdownReport.split('\n');

  for (const rawLine of rawLines) {
    const line = rawLine.trim();

    if (!line) {
      y += 3;
      continue;
    }

    // Main Headers (# or ##)
    if (line.startsWith('# ') || line.startsWith('## ')) {
      const cleanHeader = line.replace(/^#+\s*/, '');
      ensureSpace(12);
      y += 4;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(2, 132, 199); // Brand cyan/blue
      doc.text(cleanHeader, margin, y);
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(margin, y + 2, margin + contentWidth, y + 2);
      y += 6;
      continue;
    }

    // Subheaders (###)
    if (line.startsWith('### ')) {
      const cleanSub = line.replace(/^###\s*/, '');
      ensureSpace(10);
      y += 2;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(cleanSub, margin, y);
      y += 5;
      continue;
    }

    // Bullet points (- or *)
    if (line.startsWith('- ') || line.startsWith('* ')) {
      const bulletText = line.replace(/^[-*]\s*/, '');
      const wrapped = doc.splitTextToSize(bulletText, contentWidth - 8);
      ensureSpace(wrapped.length * 4.2 + 2);

      doc.setFillColor(2, 132, 199);
      doc.circle(margin + 2, y - 1, 0.8, 'F');

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(51, 65, 85);
      doc.text(wrapped, margin + 6, y);
      y += wrapped.length * 4.2 + 1.5;
      continue;
    }

    // Numbered items (1. 2.)
    if (/^\d+\.\s/.test(line)) {
      const wrapped = doc.splitTextToSize(line, contentWidth - 4);
      ensureSpace(wrapped.length * 4.2 + 2);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(51, 65, 85);
      doc.text(wrapped, margin + 2, y);
      y += wrapped.length * 4.2 + 1.5;
      continue;
    }

    // Regular paragraphs
    const wrapped = doc.splitTextToSize(line, contentWidth);
    ensureSpace(wrapped.length * 4.2 + 2);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);
    doc.text(wrapped, margin, y);
    y += wrapped.length * 4.2 + 2;
  }

  // Draw footer on final page
  drawFooter();

  // Save document
  const safeTarget = scanResult.target.replace(/[^a-zA-Z0-9_-]/g, '_');
  const dateStr = new Date().toISOString().slice(0, 10);
  const fileName = `Informe-OSINT-${safeTarget}-${dateStr}.pdf`;
  doc.save(fileName);
}
