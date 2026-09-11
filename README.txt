KOD OLD THEME + POWERFUL LINK SCANNER

1) Keep index.html as the old KOD theme.
2) Backend: npm install
3) Copy .env.example to .env and put your VirusTotal API key in VIRUSTOTAL_API_KEY. Never put the key in index.html.
4) Start: npm start
5) Open: http://localhost:3000

For GitHub Pages, index.html is static and cannot run server.js. Deploy server.js to a Node/serverless host and change fetch('/api/check-url') in index.html to your backend URL.

The scanner reports threat-intelligence detections; a clean scan is not a guarantee of safety.
