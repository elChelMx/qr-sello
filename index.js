const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { Resend } = require('resend');

const app = express();

// Puerto que Render asigna
const PORT = process.env.PORT || 3000;

// Respetar IP real detrás de proxy (Render + Cloudflare)
app.set('trust proxy', true);

// Para leer JSON (fingerprint)
app.use(express.json());

// ==== Base de datos SQLite ====
const dbPath = path.join(__dirname, 'scanlogs.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error abriendo la BD SQLite:', err);
  } else {
    console.log('BD SQLite abierta en:', dbPath);
  }
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      ip TEXT,
      ip_raw TEXT,
      x_forwarded_for TEXT,
      headers TEXT,
      user_agent TEXT,
      fp_data TEXT
    )
  `);
});

// ==== Resend (emails por API HTTP) ====
const RESEND_API_KEY = process.env.RESEND_API_KEY || null;
let resend = null;

if (!RESEND_API_KEY) {
  console.warn('RESEND_API_KEY no definida; no se enviarán correos de aviso.');
} else {
  resend = new Resend(RESEND_API_KEY);
  console.log('Resend inicializado.');
}

// Guarda un registro en la BD
function logScan({ createdAt, ip, ipRaw, xff, headers, userAgent, fpData }) {
  const stmt = db.prepare(`
    INSERT INTO scan_logs
      (created_at, ip, ip_raw, x_forwarded_for, headers, user_agent, fp_data)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    createdAt || new Date().toISOString(),
    ip || null,
    ipRaw || null,
    xff || null,
    JSON.stringify(headers || {}),
    userAgent || '',
    fpData ? JSON.stringify(fpData) : null
  );

  stmt.finalize();
}

// Envía correo "SOBRE ABIERTO" usando Resend
async function sendNotificationEmail({ createdAt, ip, userAgent }) {
  if (!resend) {
    console.warn('Resend no inicializado; se omite envío de correo.');
    return;
  }

  const to = process.env.EMAIL_TO || process.env.EMAIL_FROM;
  const from = process.env.EMAIL_FROM || 'onboarding@resend.dev';

  if (!to) {
    console.warn('EMAIL_TO no definido; se omite envío de correo.');
    return;
  }

  try {
    const { data, error } = await resend.emails.send({
      from,
      to,
      subject: 'SOBRE ABIERTO',
      text: [
        'Se ha detectado un escaneo del código de seguridad.',
        '',
        `Fecha/hora (UTC): ${createdAt}`,
        `IP: ${ip || 'desconocida'}`,
        `User-Agent: ${userAgent || ''}`,
        '',
        'Puedes consultar el detalle completo en /admin/logs o descargar /admin/logs.csv.'
      ].join('\n')
    });

    if (error) {
      console.error('Error Resend:', error);
    } else {
      console.log('Correo de aviso enviado vía Resend:', data && data.id);
    }
  } catch (err) {
    console.error('Error enviando correo vía Resend:', err);
  }
}

// ==== Rutas ====

app.get('/', (req, res) => {
  res.send('Servidor activo. Usa /scan para registrar un escaneo.');
});

// URL para el QR
app.get('/scan', (req, res) => {
  const createdAt = new Date().toISOString();
  const ip = req.ip;
  const ipRaw = req.socket.remoteAddress;
  const xff = req.headers['x-forwarded-for'] || null;
  const userAgent = req.headers['user-agent'] || '';

  // Guardar registro básico
  logScan({
    createdAt,
    ip,
    ipRaw,
    xff,
    headers: req.headers,
    userAgent,
    fpData: null
  });

  // Disparar correo (no esperamos la respuesta)
  sendNotificationEmail({ createdAt, ip, userAgent });

  // Página que ve quien escanea
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Verificación registrada</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body style="font-family: system-ui, sans-serif; padding: 1.5rem;">
  <h1>Verificación registrada</h1>
  <p>El código ha sido leído correctamente.</p>
  <p>Puede cerrar esta página.</p>

  <script>
    (function() {
      var fp = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages,
        platform: navigator.platform,
        screen: {
          width: window.screen && window.screen.width,
          height: window.screen && window.screen.height
        },
        window: {
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight
        },
        timezone: (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || null
      };

      fetch('/scan/fp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fp)
      }).catch(function(err) {
        console.error('Error enviando fingerprint', err);
      });
    })();
  </script>
</body>
</html>`);
});

// Fingerprint extra
app.post('/scan/fp', (req, res) => {
  const createdAt = new Date().toISOString();
  const ip = req.ip;
  const ipRaw = req.socket.remoteAddress;
  const xff = req.headers['x-forwarded-for'] || null;
  const userAgent = req.headers['user-agent'] || '';
  const fpPayload = req.body || null;

  logScan({
    createdAt,
    ip,
    ipRaw,
    xff,
    headers: req.headers,
    userAgent,
    fpData: fpPayload
  });

  res.status(204).end();
});

// Ver logs JSON
app.get('/admin/logs', (req, res) => {
  db.all('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 100', (err, rows) => {
    if (err) {
      console.error('Error al consultar la base de datos', err);
      return res.status(500).send('Error consultando la base de datos');
    }
    res.json(rows);
  });
});

// Descargar CSV
app.get('/admin/logs.csv', (req, res) => {
  db.all('SELECT * FROM scan_logs ORDER BY id DESC', (err, rows) => {
    if (err) {
      console.error('Error al consultar la base de datos', err);
      return res.status(500).send('Error consultando la base de datos');
    }

    function csvEscape(value) {
      if (value === null || value === undefined) return '""';
      const str = String(value).replace(/"/g, '""');
      return '"' + str + '"';
    }

    const header = [
      'id',
      'created_at',
      'ip',
      'ip_raw',
      'x_forwarded_for',
      'user_agent',
      'fp_data'
    ].join(',') + '\\n';

    const lines = rows.map(row => {
      return [
        csvEscape(row.id),
        csvEscape(row.created_at),
        csvEscape(row.ip),
        csvEscape(row.ip_raw),
        csvEscape(row.x_forwarded_for),
        csvEscape(row.user_agent),
        csvEscape(row.fp_data)
      ].join(',');
    });

    const csv = header + lines.join('\\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="scan_logs.csv"');
    res.send(csv);
  });
});

app.listen(PORT, () => {
  console.log('Servidor escuchando en puerto ' + PORT);
});
