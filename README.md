# matascam
Matascam sirve para combatir los sitios de fraude, phishing y estafa - única el reporte y permite exportar resultados a excel para seguimiento en NodeJS.

CLI profesional para reportar phishing, scam y spam, con exportación a Excel y múltiples campos/sitios de reporte.

## Características
- Reporta sitios sospechosos a más de 25 servicios internacionales y redes sociales
- Registra historial en CSV y JSON
- Exporta historial a Excel (.xlsx)
- Campos extra: email, teléfono, empresa, red social
- Sugerencias automáticas de motivo y categoría
- Obtiene IP, país, WHOIS y reputación

## Instalación
1. Instala Node.js (v18+ recomendado)
2. Instala dependencias:
   ```bash
   npm install inquirer open axios whois csv-writer chalk exceljs
   ```
3. (Opcional) Agrega tus API keys en el archivo:
   ```js
   const API_KEYS = {
     virustotal: "",
     abuseipdb: "",
     phishtank: "",
     safebrowsing: "",
   };
   ```
4. Agrega a tu `package.json`:
   ```json
   {
     "type": "module"
   }
   ```

## Uso
```bash
node matascam_pro_excel.js
```

### Opciones del menú
- **Reportar sitio**: Ingresa la URL y datos relacionados, selecciona servicios para reportar, y guarda el registro.
- **Ver historial de reportes**: Muestra el historial en consola.
- **Exportar historial a Excel**: Genera el archivo `matascam_reports.xlsx` con todos los reportes.
- **Salir**: Finaliza la aplicación.

## Exportación a Excel
El historial se guarda en `matascam_reports.json` y puede exportarse a `matascam_reports.xlsx` desde el menú.

## Requisitos
- Node.js
- Acceso a internet para APIs y reportes
