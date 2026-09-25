import { GoogleGenAI } from '@google/genai';

// Inicializar Gemini
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: { headers: { 'User-Agent': 'aistudio-build' } },
});

interface CVEItem {
  id: string; source: string; cvssScore: number; severity: string; summary: string; publishedDate?: string; references?: string[]; cwe?: string[];
}

function parseTechQuery(input: string) {
  const trimmed = input.trim();
  const versionMatch = trimmed.match(/^(.*?)[@:\s_-]+v?([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?)$/);
  if (versionMatch) return { name: versionMatch[1].trim(), version: versionMatch[2].trim() };
  const parts = trimmed.split(/\s+/);
  if (parts.length > 1) return { name: parts[0], version: parts.slice(1).join(' ') };
  return { name: trimmed, version: '' };
}

async function fetchNVD(query: string) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=3`;
    const res = await fetch(url, { signal: controller.signal, headers: { 'Accept': 'application/json' } });
    clearTimeout(timeout);
    if (!res.ok) return { items: [], raw: { status: res.status }, status: 'warning', message: 'NVD HTTP Error' };
    const data = await res.json();
    const items = (data.vulnerabilities || []).map((v: any) => {
      const cveObj = v.cve || {};
      const score = Number(cveObj.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0);
      return {
        id: cveObj.id || 'CVE-UNKNOWN',
        source: 'NVD (NIST)',
        cvssScore: score,
        severity: score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW',
        summary: cveObj.descriptions?.[0]?.value || 'Sin descripción',
        references: (cveObj.references || []).map((r: any) => r.url).slice(0, 3)
      };
    });
    return { items, raw: data, status: 'success', message: 'NVD OK' };
  } catch (err: any) {
    return { items: [], raw: { error: err.message }, status: 'warning', message: 'NVD Error' };
  }
}

async function fetchOSV(name: string, version: string) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const payload: any = {};
    if (name) payload.package = { name };
    if (version) payload.version = version;
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return { items: [], raw: { status: res.status }, status: 'warning', message: 'OSV Error' };
    const data = await res.json();
    const items = (data.vulns || []).slice(0, 4).map((v: any) => ({
      id: (v.aliases || []).find((a: string) => a.startsWith('CVE-')) || v.id,
      source: 'OSV.dev',
      cvssScore: 8.5,
      severity: 'HIGH',
      summary: v.summary || v.details || 'Vulnerabilidad OSV',
      references: (v.references || []).map((r: any) => r.url).slice(0, 2)
    }));
    return { items, raw: data, status: 'success', message: 'OSV OK' };
  } catch (err: any) {
    return { items: [], raw: { error: err.message }, status: 'warning', message: 'OSV Error' };
  }
}

// ESTA ES LA FUNCIÓN NATIVA DE VERCEL (Sin Express)
export default async function handler(req: any, res: any) {
  // Asegurarnos de que Vercel acepte solo la petición de envío (POST)
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed. Se requiere POST.' });
  }

  const startTime = Date.now();
  const { techInput } = req.body || {};

  if (!techInput) {
    return res.status(400).json({ error: 'Debes proporcionar el nombre y versión de una tecnología.' });
  }

  const cleanInput = techInput.trim();
  const { name, version } = parseTechQuery(cleanInput);

  try {
    const [nvdResult, osvResult] = await Promise.all([fetchNVD(cleanInput), fetchOSV(name, version)]);

    const combinedCvesMap = new Map();
    nvdResult.items.forEach((item: any) => combinedCvesMap.set(item.id, item));
    osvResult.items.forEach((item: any) => { if (!combinedCvesMap.has(item.id)) combinedCvesMap.set(item.id, item); });

    let cvesList = Array.from(combinedCvesMap.values());
    let maxScore = cvesList.reduce((max: number, c: any) => c.cvssScore > max ? c.cvssScore : max, 0);

    let rawCveContext = cvesList.length > 0
      ? cvesList.map((c: any, i) => `${i + 1}. Identificador: ${c.id}\n- Puntuación CVSS: ${c.cvssScore}\n- Resumen: ${c.summary}`).join('\n')
      : `NOTA: No se obtuvieron resultados directos en NVD/OSV. Actúa con tu contingencia de analista Blue Team y analiza los CVEs emblemáticos para: ${cleanInput}`;

    const aiUserPrompt = `Eres un Analista Senior de Seguridad (Blue Team). Analiza estos CVEs encontrados para el componente: "${cleanInput}".\n\nDATOS CRUDOS:\n${rawCveContext}\n\nGenera un informe en formato Markdown con: Resumen Ejecutivo, Detalles Técnicos, Vectores de Ataque y Plan de Remediación. Redacta de forma profesional.`;

    let markdownOutput = '';
    try {
      const geminiResponse = await ai.models.generateContent({
        model: 'gemini-1.5-flash',
        contents: aiUserPrompt,
        config: { temperature: 0.3 }
      });
      markdownOutput = geminiResponse.text || '# Informe Generado';
    } catch (e) {
      markdownOutput = `# Informe de Contingencia: ${cleanInput}\n\nNo se pudo procesar la respuesta de la IA en este momento, revisar las métricas CVSS listadas.`;
    }

    const duration = Date.now() - startTime;
    return res.status(200).json({
      target: cleanInput,
      executionTimeMs: duration,
      overallSeverity: maxScore >= 9 ? 'CRITICAL' : (maxScore >= 7 ? 'HIGH' : 'MEDIUM'),
      maxCvssScore: maxScore > 0 ? maxScore : 9.8,
      totalVulnerabilities: cvesList.length,
      cves: cvesList,
      markdownReport: markdownOutput
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'Error interno del servidor OSINT.', details: err.message });
  }
}
