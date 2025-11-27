const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();

// Render te pasa el puerto en process.env.PORT
const PORT = process.env.PORT || 3000;

// Respeta X-Forwarded-For detrás de proxy
app.set('trust proxy', true);

// Para leer JSON (fingerprint)
app.use(express.json());

// === Inicializar base de datos SQLite ===
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

// === Configuración de SMTP para enviar correo ===
// Para Outlook/Hotmail se suele usar smtp-mail.outlook.com puerto 587 con STARTTLS 
const smtpHost = process.env.SMTP_HOST || 'smtp-mail.outlook.com';
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;

let mailer = null;

if (smtpUser && smtpPass) {
  mailer = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: false, // TLS explícito en 587
    auth: {
      user: smtpUser,
      pass: smtpPass
    }
  });
} else {
  console.warn('SMTP_USER o SMTP_PASS no definidos; no se enviarán correos de aviso.');
}

// Función para registrar un escaneo
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

// Enviar correo de notificación
function sendNotificationEmail({ createdAt, ip, userAgent }) {
  if (!mailer) {
    console.warn('Mailer no configurado; se omite envío de correo.');
    return;
  }

  const to = process.env.EMAIL_TO || smtpUser;
  const from = process.env.EMAIL_FROM || smtpUser;

  const text = [
    'Se ha detectado un escaneo del código de seguridad.',
    '',
    `Fecha/hora (UTC): ${createdAt}`,
    `IP: ${ip || 'desconocida'}`,
    `User-Agent: ${userAgent || ''}`,
    '',
    'Puedes consultar el detalle completo en /admin/logs o descargar /admin/logs.csv.'
  ].join('\n');

  mailer.sendMail(
    {
      from,
      to,
      subject: 'SOBRE ABIERTO',
      text
    },
    (err, info) => {
      if (err) {
        console.error('Error enviando correo de aviso:', err);
      } else {
        console.log('Correo de aviso enviado:', info && info.messageId);
      }
    }
  );
}

// Ruta básica para comprobar que el servidor responde
app.get('/', (req, res) => {
  res.send('Servidor activo. Usa /scan para registrar un escaneo.');
});

// === URL que irá en el QR ===
app.get('/scan', (req, res) => {
  const createdAt = new Date().toISOString();
  const ip = req.ip;
  const ipRaw = req.socket.remoteAddress;
  const xff = req.headers['x-forwarded-for'] || null;
  const userAgent = req.headers['user-agent'] || '';

  // Registro servidor (IP + headers)
  logScan({
    createdAt,
    ip,
    ipRaw,
    xff,
    headers: req.headers,
    userAgent,
    fpData: null
  });

  // Enviar correo de aviso
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
      // Fingerprint sencillo del navegador
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

// === Endpoint que recibe el fingerprint ===
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

  res.status(204).end(); // sin contenido
});

// === Ver los últimos registros (para ti) ===
app.get('/admin/logs', (req, res) => {
  db.all('SELECT * FROM scan_logs ORDER BY id DESC LIMIT 100', (err, rows) => {
    if (err) {
      console.error('Error al consultar la base de datos', err);
      return res.status(500).send('Error consultando la base de datos');
    }
    res.json(rows);
  });
});

// === Descargar registros en CSV ===
app.get('/admin/logs.csv', (req, res) => {
  db.all('SELECT * FROM scan_logs ORDER BY id DESC', (err, rows) => {
    if (err) {
      console.error('Error al consultar la base de datos', err);
      return res.status(500).send('Error consultando la base de datos');
    }

    function csvEscape(value) {
      if (value === null || value === undefined) return '""';
      const str = String(value).replace(/"/g, '""');
      return `"${str}"`;
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
