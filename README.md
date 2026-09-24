# Omni-Vuln Scanner 🛡️
**AI-Powered OSINT Threat Intelligence & Vulnerability Analyzer**

Omni-Vuln Scanner es una herramienta de Inteligencia de Amenazas (Threat Intelligence) de código abierto diseñada para equipos de Blue Team y analistas SOC. Su objetivo es automatizar la consulta de bases de datos públicas de vulnerabilidades (NVD, OSV) y utilizar Modelos de Lenguaje Grande (LLMs) para traducir datos técnicos crudos (JSON) en informes de auditoría procesables, estructurados y comprensibles.

---

## 🚀 Características Principales

*   **Análisis Pasivo (Zero-Impact):** A diferencia de escáneres activos de infraestructura (como Nessus o OpenVAS), Omni-Vuln realiza auditorías puramente OSINT (Open Source Intelligence). No envía paquetes de red ni interactúa con servidores de producción, garantizando un riesgo operativo nulo.
*   **Orquestación de APIs:** Integración asíncrona con el National Vulnerability Database (NVD NIST) y Open Source Vulnerabilities (OSV.dev) para la ingesta de datos empíricos de N-Days y CVEs conocidos.
*   **Traducción de Amenazas mediante IA:** Utiliza Google Gemini para ingerir los resultados de las APIs y generar automáticamente un informe dual: un resumen ejecutivo para gerencia y un desglose técnico preciso con vectores de ataque y planes de remediación para ingenieros.
*   **Caché de Historial Local:** Implementa almacenamiento en el navegador (`localStorage`) para guardar escaneos previos, optimizando la experiencia del usuario y protegiendo la aplicación contra los *rate limits* (límites de peticiones) de las APIs públicas.

## 🏗️ Arquitectura del Flujo de Trabajo

1.  **Reconocimiento:** El usuario introduce una tecnología y su versión exacta (ej. `log4j 2.14.0` o `apache 2.4.49`).
2.  **Ingesta de Datos:** La aplicación consulta las APIs de NVD y OSV.
3.  **Procesamiento LLM:** Los datos JSON crudos y las puntuaciones CVSS se inyectan en un *System Prompt* de seguridad defensiva.
4.  **Generación de Reporte:** La IA devuelve un informe estructurado en formato Markdown, resaltando dependencias críticas, impacto y mitigación.

## ⚠️ Limitaciones Conocidas y Casos de Uso (Disclaimer)

Para mantener la integridad técnica de la herramienta, es vital comprender sus limitaciones inherentes por diseño:

*   **Desfase de Indexación (Falsos Positivos en Parches Recientes):** Al auditar versiones de software liberadas recientemente (ej. un parche de emergencia lanzado hace 24 horas), la API de NVD puede devolver vulnerabilidades de la rama anterior debido a retrasos en la indexación de etiquetas. La herramienta prioriza mostrar el riesgo asociado a la familia del software; **el triaje final y la verificación del parche siguen siendo responsabilidad del analista humano.**
*   **No es una herramienta SAST/DAST:** Omni-Vuln no analiza código fuente propietario ni busca vulnerabilidades *Zero-Day* no descubiertas. Audita exclusivamente software y dependencias de terceros públicas.

## 🛠️ Stack Tecnológico

*   **Frontend:** HTML5, CSS3 (Dark Theme/SOC UI), JavaScript (ES6+).
*   **Integraciones / APIs:** REST API (NVD NIST), OSV API.
*   **Motor de Inteligencia Artificial:** Google Gemini API (Function Calling & Prompt Engineering).

## 📥 Instalación y Uso Local

1. Clona este repositorio:
   ```bash
   git clone [https://github.com/noemigondel-ia/omni-vuln-scanner.git](https://github.com/noemigondel-ia/omni-vuln-scanner.git)
