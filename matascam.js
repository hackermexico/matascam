#!/usr/bin/env node
/**
 * matascam_pro_excel - CLI profesional para reportar phishing/scam/spam con exportación a Excel y más campos/sitios de reporte
 */
import inquirer from "inquirer";
import open from "open";
import axios from "axios";
import whois from "whois";
import fs from "fs";
import { createObjectCsvWriter } from "csv-writer";
import chalk from "chalk";
import ExcelJS from "exceljs";
import { URL } from "url";
import dns from "dns";
const dnsPromises = dns.promises;

const API_KEYS = {
  virustotal: "",
  abuseipdb: "",
  phishtank: "",
  safebrowsing: "",
};

const LOG_FILE = "matascam_reports.csv";
const LOG_JSON = "matascam_reports.json";

const REPORTERS = [
  { name: "Google Safe Browsing", url: "https://safebrowsing.google.com/safebrowsing/report_phish/" },
  { name: "Microsoft Security Intelligence", url: "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site" },
  { name: "SpamCop", url: "https://www.spamcop.net/" },
  { name: "APWG", url: "https://apwg.org/report-phishing/" },
  { name: "Cloudflare Security", url: "https://www.cloudflare.com/abuse/phishing/" },
  { name: "PhishTank", url: "https://phishtank.org/" },
  { name: "CERT-MX", url: "https://www.gob.mx/csirtmx" },
  { name: "VirusTotal", url: "https://www.virustotal.com/gui/home/url" },
  { name: "AbuseIPDB", url: "https://www.abuseipdb.com/" },
  { name: "Kaspersky OpenTIP", url: "https://opentip.kaspersky.com/" },
  { name: "Trend Micro Site Safety", url: "https://global.sitesafety.trendmicro.com/" },
  { name: "US-CERT (CISA)", url: "https://www.cisa.gov/report" },
  { name: "FTC Fraud Report", url: "https://reportfraud.ftc.gov/" },
  { name: "ESET Report", url: "https://www.eset.com/int/report/" },
  { name: "Bitdefender", url: "https://www.bitdefender.com/support/how-to-report-a-malicious-webpage-1101.html" },
  { name: "Norton/Symantec", url: "https://submit.symantec.com/false_positive/" },
  { name: "Scamwatch Australia", url: "https://www.scamwatch.gov.au/report-a-scam" },
  { name: "Europol EC3", url: "https://www.europol.europa.eu/report-a-crime-online" },
  { name: "INTERPOL", url: "https://www.interpol.int/en/Crimes/Cybercrime/Cybercrime-reporting" },
  { name: "CyberTipline NCMEC", url: "https://report.cybertip.org/" },
  { name: "Google Formulario de Fraude", url: "https://support.google.com/mail/contact/abuse" },
  { name: "Meta/Facebook", url: "https://www.facebook.com/help/contact/169486816475808" },
  { name: "Twitter/X", url: "https://help.twitter.com/forms/abusive-user" },
  { name: "Reddit", url: "https://www.reddit.com/report" },
  { name: "LinkedIn", url: "https://www.linkedin.com/help/linkedin/ask/TS-NC?lang=es" },
];

const MOTIVOS = [
  "Phishing",
  "Scam",
  "Spam",
  "Malware",
  "Fraude financiero",
  "Suplantación de identidad",
  "Venta ilegal",
  "Contenido ilegal",
  "Botnet",
  "Ransomware",
  "Otros",
];

const CATEGORIAS = [
  "Banca",
  "Correo electrónico",
  "Redes sociales",
  "Criptomonedas",
  "E-commerce",
  "Gobierno",
  "Educación",
  "Salud",
  "Entretenimiento",
  "Otros",
];

function normalizeUrl(url) {
  try {
    let u = new URL(url);
    return u.href;
  } catch {
    if (!/^https?:\/\//.test(url)) url = "http://" + url;
    try {
      let u = new URL(url);
      return u.href;
    } catch {
      return null;
    }
  }
}

function logReport(data) {
  const csvWriter = createObjectCsvWriter({
    path: LOG_FILE,
    header: [
      { id: "timestamp", title: "Timestamp" },
      { id: "url", title: "URL" },
      { id: "motivo", title: "Motivo" },
      { id: "categoria", title: "Categoria" },
      { id: "descripcion", title: "Descripcion" },
      { id: "pais", title: "Pais" },
      { id: "ip", title: "IP" },
      { id: "whois", title: "WHOIS" },
      { id: "reputation", title: "Reputation" },
      { id: "services", title: "Services" },
      { id: "email", title: "Email" },
      { id: "telefono", title: "Telefono" },
      { id: "empresa", title: "Empresa" },
      { id: "red_social", title: "RedSocial" },
    ],
    append: true,
  });
  csvWriter.writeRecords([data]);
  fs.appendFileSync(LOG_JSON, JSON.stringify(data) + "\n");
}

async function exportToExcel() {
  if (!fs.existsSync(LOG_JSON)) {
    console.log(chalk.yellow("No hay reportes para exportar."));
    return;
  }
  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet("Reportes");
  sheet.columns = [
    { header: "Timestamp", key: "timestamp", width: 24 },
    { header: "URL", key: "url", width: 40 },
    { header: "Motivo", key: "motivo", width: 16 },
    { header: "Categoria", key: "categoria", width: 16 },
    { header: "Descripcion", key: "descripcion", width: 32 },
    { header: "Pais", key: "pais", width: 16 },
    { header: "IP", key: "ip", width: 16 },
    { header: "WHOIS", key: "whois", width: 32 },
    { header: "Reputation", key: "reputation", width: 16 },
    { header: "Services", key: "services", width: 32 },
    { header: "Email", key: "email", width: 24 },
    { header: "Telefono", key: "telefono", width: 16 },
    { header: "Empresa", key: "empresa", width: 24 },
    { header: "RedSocial", key: "red_social", width: 24 },
  ];
  const lines = fs.readFileSync(LOG_JSON, "utf8").split("\n").filter(Boolean);
  for (const line of lines) {
    try {
      sheet.addRow(JSON.parse(line));
    } catch {}
  }
  await workbook.xlsx.writeFile("matascam_reports.xlsx");
  console.log(chalk.green("Exportado a matascam_reports.xlsx"));
}

async function getIP(domain) {
  try {
    let addresses = await dnsPromises.lookup(domain);
    return addresses.address || "";
  } catch (err) {
    return "";
  }
}

function getWhois(domain) {
  return new Promise((resolve) => {
    whois.lookup(domain, (err, data) => {
      resolve(data || "");
    });
  });
}

async function checkVirusTotal(url) {
  if (!API_KEYS.virustotal) return "No API key";
  try {
    let r = await axios.get("https://www.virustotal.com/api/v3/urls", {
      params: { url },
      headers: { "x-apikey": API_KEYS.virustotal },
    });
    return r.data.data ? "Reported" : "Clean";
  } catch (e) {
    return "Error";
  }
}

async function checkAbuseIPDB(ip) {
  if (!API_KEYS.abuseipdb) return "No API key";
  try {
    let r = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: ip },
      headers: { "Key": API_KEYS.abuseipdb, "Accept": "application/json" },
    });
    return r.data.data.abuseConfidenceScore > 0 ? "Reported" : "Clean";
  } catch (e) {
    return "Error";
  }
}

async function showHistory() {
  if (!fs.existsSync(LOG_FILE)) {
    console.log(chalk.yellow("No hay historial de reportes."));
    return;
  }
  let data = fs.readFileSync(LOG_FILE, "utf8");
  console.log(chalk.cyan("\n=== Historial de reportes ===\n"));
  console.log(data);
}

function suggestMotivo(url) {
  if (/bank|paypal|banco|finance|card/i.test(url)) return "Phishing";
  if (/crypto|bitcoin|wallet/i.test(url)) return "Fraude financiero";
  if (/mail|email/i.test(url)) return "Phishing";
  if (/gov|gobierno/i.test(url)) return "Suplantación de identidad";
  if (/shop|store|ecommerce/i.test(url)) return "Venta ilegal";
  return "Phishing";
}

function suggestCategoria(url) {
  if (/bank|paypal|banco|finance|card/i.test(url)) return "Banca";
  if (/crypto|bitcoin|wallet/i.test(url)) return "Criptomonedas";
  if (/mail|email/i.test(url)) return "Correo electrónico";
  if (/gov|gobierno/i.test(url)) return "Gobierno";
  if (/shop|store|ecommerce/i.test(url)) return "E-commerce";
  return "Otros";
}

function suggestDescripcion(url) {
  return `Sitio detectado como sospechoso por patrones de phishing/scam/spam. URL: ${url}`;
}

function getCountry(ip) {
  return axios.get(`https://ipapi.co/${ip}/country_name/`)
    .then(r => r.data)
    .catch(() => "Desconocido");
}

async function main() {
  console.clear();
  console.log(chalk.bold.cyan("🔒 MATASCAM PRO - Reportador Profesional de Phishing/Scams"));
  console.log(chalk.cyan("=========================================\n"));

  const { action } = await inquirer.prompt([
    {
      type: "list",
      name: "action",
      message: "¿Qué deseas hacer?",
      choices: [
        { name: "Reportar sitio", value: "report" },
        { name: "Ver historial de reportes", value: "history" },
        { name: "Exportar historial a Excel", value: "excel" },
        { name: "Salir", value: "exit" },
      ],
    },
  ]);
  if (action === "history") {
    await showHistory();
    return;
  }
  if (action === "excel") {
    await exportToExcel();
    return;
  }
  if (action === "exit") return;

  // Solicitar URL y prellenar campos
  const { phishingURL, email, telefono, empresa, red_social } = await inquirer.prompt([
    { type: "input", name: "phishingURL", message: "🔗 URL sospechosa:" },
    { type: "input", name: "email", message: "Correo relacionado (opcional):" },
    { type: "input", name: "telefono", message: "Teléfono relacionado (opcional):" },
    { type: "input", name: "empresa", message: "Empresa/Marca afectada (opcional):" },
    { type: "input", name: "red_social", message: "Red social involucrada (opcional):" },
  ]);
  let url = normalizeUrl(phishingURL);
  if (!url) {
    console.log(chalk.red("❌ URL inválida."));
    return;
  }
  let domain = url.replace(/^https?:\/\//, "").split("/")[0];
  let motivo = suggestMotivo(url);
  let categoria = suggestCategoria(url);
  let descripcion = suggestDescripcion(url);

  // IP, país, WHOIS, reputación
  let ip = await getIP(domain);
  let pais = ip ? await getCountry(ip) : "Desconocido";
  let whoisData = await getWhois(domain);
  let reputation = {};
  if (API_KEYS.virustotal) reputation.virustotal = await checkVirusTotal(url);
  if (API_KEYS.abuseipdb && ip) reputation.abuseipdb = await checkAbuseIPDB(ip);

  // Confirmar/prellenar campos
  const answers = await inquirer.prompt([
    { type: "list", name: "motivo", message: "Motivo del reporte:", choices: MOTIVOS, default: motivo },
    { type: "list", name: "categoria", message: "Categoría:", choices: CATEGORIAS, default: categoria },
    { type: "input", name: "descripcion", message: "Descripción:", default: descripcion },
    { type: "input", name: "pais", message: "País (auto):", default: pais },
    { type: "input", name: "email", message: "Correo relacionado (opcional):", default: email },
    { type: "input", name: "telefono", message: "Teléfono relacionado (opcional):", default: telefono },
    { type: "input", name: "empresa", message: "Empresa/Marca afectada (opcional):", default: empresa },
    { type: "input", name: "red_social", message: "Red social involucrada (opcional):", default: red_social },
  ]);

  // Elegir servicios para reportar
  const { selectedServices } = await inquirer.prompt([
    {
      type: "checkbox",
      name: "selectedServices",
      message: "📡 Elige los servicios donde quieres reportar:",
      choices: REPORTERS.map(r => r.name),
      default: ["Google Safe Browsing", "Microsoft Security Intelligence", "APWG"],
    },
  ]);

  // Procesar selección
  for (const serviceName of selectedServices) {
    const reporter = REPORTERS.find(r => r.name === serviceName);
    if (reporter) {
      console.log(chalk.green(`➡️  Abriendo ${serviceName}...`));
      await open(reporter.url);
    }
  }

  // Log
  logReport({
    timestamp: new Date().toISOString(),
    url,
    motivo: answers.motivo,
    categoria: answers.categoria,
    descripcion: answers.descripcion,
    pais: answers.pais,
    ip,
    whois: whoisData.slice(0, 200),
    reputation: JSON.stringify(reputation),
    services: selectedServices.join(", "),
    email: answers.email,
    telefono: answers.telefono,
    empresa: answers.empresa,
    red_social: answers.red_social,
  });

  console.log(chalk.bold.green("\n✅ ¡Listo! Completa los formularios manualmente (algunos usan CAPTCHA o autenticación)."));
  console.log(chalk.cyan("💡 Sugerencia: puedes automatizar envíos vía API donde esté disponible, integrando peticiones fetch/axios.\n"));
}

main().catch(err => {
  console.error(chalk.red("❌ Error:"), err);
});
