const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = 3000;

// Base de datos SQLite
const db = new sqlite3.Database('./database.db');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'secreto-super-inseguro-123',
    resave: false,
    saveUninitialized: true
}));

// Inicializar base de datos
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        rol TEXT CHECK(rol IN ('root', 'usuario'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS datos_sensibles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT,
        contenido TEXT,
        propietario_id INTEGER,
        nivel_acceso TEXT CHECK(nivel_acceso IN ('publico', 'privado', 'admin'))
    )`);

    // Insertar usuarios de prueba
    db.run(`INSERT OR IGNORE INTO usuarios (id, username, password, rol) VALUES (1, 'root', 'root123', 'root')`);
    db.run(`INSERT OR IGNORE INTO usuarios (id, username, password, rol) VALUES (2, 'usuario1', 'user123', 'usuario')`);
    db.run(`INSERT OR IGNORE INTO usuarios (id, username, password, rol) VALUES (3, 'usuario2', 'user456', 'usuario')`);

    // Insertar datos de prueba
    db.run(`INSERT OR IGNORE INTO datos_sensibles (id, titulo, contenido, propietario_id, nivel_acceso) VALUES (1, 'Info pública', 'Contenido visible para todos', 1, 'publico')`);
    db.run(`INSERT OR IGNORE INTO datos_sensibles (id, titulo, contenido, propietario_id, nivel_acceso) VALUES (2, 'Datos privados usuario1', 'Información confidencial del usuario 1', 2, 'privado')`);
    db.run(`INSERT OR IGNORE INTO datos_sensibles (id, titulo, contenido, propietario_id, nivel_acceso) VALUES (3, 'Secretos del sistema', 'Credenciales y configuraciones críticas', 1, 'admin')`);
});

// ============================================
// VULNERABILIDAD 1: Autenticación débil
// No hay validación adecuada, contraseñas en texto plano
// ============================================
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // VULNERABILIDAD: SQL Injection - concatenación directa
    const query = `SELECT * FROM usuarios WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, (err, row) => {
        if (err) {
            return res.status(500).send('Error en la base de datos');
        }
        if (row) {
            req.session.userId = row.id;
            req.session.username = row.username;
            req.session.rol = row.rol;
            res.redirect('/dashboard');
        } else {
            res.send('Credenciales incorrectas');
        }
    });
});

// ============================================
// VULNERABILIDAD 2: Control de acceso roto
// Cualquier usuario puede ver datos de admin
// ============================================
app.get('/datos/:id', (req, res) => {
    const datoId = req.params.id;

    // VULNERABILIDAD: No se verifica si el usuario tiene permiso para ver este dato
    // Un usuario normal puede ver datos de nivel 'admin'
    const query = `SELECT * FROM datos_sensibles WHERE id = ${datoId}`;

    db.get(query, (err, row) => {
        if (err || !row) {
            return res.status(404).send('Dato no encontrado');
        }
        res.json(row);
    });
});

// ============================================
// VULNERABILIDAD 3: Escalada de privilegios
// Cualquier usuario puede cambiar su rol a 'root'
// ============================================
app.post('/cambiar-rol', (req, res) => {
    const { nuevoRol } = req.body;
    const userId = req.session.userId;

    // VULNERABILIDAD: No se verifica si el usuario actual es root
    // Cualquier usuario puede cambiar su propio rol
    db.run(`UPDATE usuarios SET rol = '${nuevoRol}' WHERE id = ${userId}`, (err) => {
        if (err) {
            return res.status(500).send('Error');
        }
        req.session.rol = nuevoRol;
        res.send('Rol actualizado a: ' + nuevoRol);
    });
});

// ============================================
// VULNERABILIDAD 4: IDOR (Insecure Direct Object Reference)
// Los usuarios pueden ver datos de otros usuarios
// ============================================
app.get('/perfil/:userId', (req, res) => {
    const targetUserId = req.params.userId;

    // VULNERABILIDAD: No se verifica si el usuario autenticado tiene derecho a ver este perfil
    const query = `SELECT id, username, rol FROM usuarios WHERE id = ${targetUserId}`;

    db.get(query, (err, row) => {
        if (err || !row) {
            return res.status(404).send('Usuario no encontrado');
        }
        res.json(row);
    });
});

// ============================================
// VULNERABILIDAD 5: Búsqueda con SQL Injection
// ============================================
app.get('/buscar', (req, res) => {
    const termino = req.query.q;

    // VULNERABILIDAD: SQL Injection en búsqueda
    const query = `SELECT * FROM datos_sensibles WHERE titulo LIKE '%${termino}%' OR contenido LIKE '%${termino}%'`;

    db.all(query, (err, rows) => {
        if (err) {
            return res.status(500).send('Error en búsqueda');
        }
        res.json(rows);
    });
});

// ============================================
// VULNERABILIDAD 6: Eliminación sin autorización
// Cualquier usuario puede eliminar datos
// ============================================
app.post('/eliminar/:id', (req, res) => {
    const datoId = req.params.id;

    // VULNERABILIDAD: No se verifica el rol del usuario ni la propiedad del dato
    db.run(`DELETE FROM datos_sensibles WHERE id = ${datoId}`, (err) => {
        if (err) {
            return res.status(500).send('Error al eliminar');
        }
        res.send('Dato eliminado');
    });
});

// ============================================
// VULNERABILIDAD 7: Información sensible expuesta
// Endpoint que muestra todos los usuarios sin autenticación
// ============================================
app.get('/api/usuarios', (req, res) => {
    // VULNERABILIDAD: No requiere autenticación
    db.all(`SELECT id, username, rol FROM usuarios`, (err, rows) => {
        if (err) {
            return res.status(500).send('Error');
        }
        res.json(rows);
    });
});

// ============================================
// VULNERABILIDAD 8: Ejecución de comandos (simulada)
// ============================================
app.post('/ejecutar-comando', (req, res) => {
    const { comando } = req.body;

    // VULNERABILIDAD: En un caso real, esto podría ejecutar comandos del sistema
    // Aquí simulamos que solo root debería poder hacerlo
    if (req.session.rol === 'root') {
        res.send(`Comando ejecutado: ${comando}`);
    } else {
        // VULNERABILIDAD: La respuesta revela que el comando existe
        res.status(403).send('Acceso denegado. Este comando requiere privilegios de root.');
    }
});

// Dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }

    db.all(`SELECT * FROM datos_sensibles`, (err, datos) => {
        if (err) {
            return res.status(500).send('Error');
        }

        let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - App Vulnerable</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
                .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
                .badge-root { background: #ff4444; color: white; }
                .badge-usuario { background: #4444ff; color: white; }
                .datos-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-top: 20px; }
                .dato-card { border: 1px solid #ddd; padding: 15px; border-radius: 6px; }
                .nivel-admin { border-left: 4px solid #ff4444; }
                .nivel-privado { border-left: 4px solid #ffaa00; }
                .nivel-publico { border-left: 4px solid #44ff44; }
                .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; margin: 2px; }
                .btn-danger { background: #ff4444; color: white; }
                .btn-warning { background: #ffaa00; color: white; }
                .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
                .alert-warning { background: #fff3cd; border: 1px solid #ffc107; }
                .nav { margin-bottom: 20px; }
                .nav a { margin-right: 15px; color: #0066cc; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Dashboard</h1>
                    <div>
                        <span class="badge ${req.session.rol === 'root' ? 'badge-root' : 'badge-usuario'}">${req.session.rol.toUpperCase()}</span>
                        <span>${req.session.username}</span>
                        <a href="/logout" class="btn btn-warning">Cerrar sesión</a>
                    </div>
                </div>

                <div class="alert alert-warning">
                    <strong>⚠️ APLICACIÓN VULNERABLE - SOLO PARA USO EDUCATIVO</strong><br>
                    Esta aplicación contiene vulnerabilidades intencionales para aprendizaje de seguridad.
                </div>

                <div class="nav">
                    <a href="/">Inicio</a>
                    <a href="/dashboard">Dashboard</a>
                    <a href="/admin">Panel Admin (Vulnerable)</a>
                </div>

                <h2>Datos del sistema</h2>
                <div class="datos-grid">
        `;

        datos.forEach(dato => {
            html += `
                    <div class="dato-card nivel-${dato.nivel_acceso}">
                        <h3>${dato.titulo}</h3>
                        <p>${dato.contenido}</p>
                        <small>Nivel: ${dato.nivel_acceso} | Propietario ID: ${dato.propietario_id}</small><br>
                        <button class="btn btn-danger" onclick="eliminar(${dato.id})">Eliminar</button>
                        <a href="/datos/${dato.id}" class="btn btn-warning">Ver JSON</a>
                    </div>
            `;
        });

        html += `
                </div>

                <h2 style="margin-top: 30px;">Búsqueda (Vulnerable a SQL Injection)</h2>
                <form action="/buscar" method="GET">
                    <input type="text" name="q" placeholder="Buscar..." style="padding: 8px; width: 300px;">
                    <button type="submit" class="btn btn-warning">Buscar</button>
                </form>
                <p><small>Prueba con: ' OR '1'='1</small></p>

                <h2 style="margin-top: 30px;">Cambiar Rol (Vulnerable - Escalada de privilegios)</h2>
                <form action="/cambiar-rol" method="POST">
                    <select name="nuevoRol">
                        <option value="usuario">usuario</option>
                        <option value="root">root</option>
                    </select>
                    <button type="submit" class="btn btn-danger">Cambiar mi rol</button>
                </form>
            </div>

            <script>
                function eliminar(id) {
                    if (confirm('¿Eliminar este dato?')) {
                        fetch('/eliminar/' + id, { method: 'POST' })
                            .then(() => location.reload());
                    }
                }
            </script>
        </body>
        </html>
        `;

        res.send(html);
    });
});

// Panel admin (vulnerable)
app.get('/admin', (req, res) => {
    // VULNERABILIDAD: No se verifica si el usuario es root
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Panel Admin</title></head>
        <body>
            <h1>Panel de Administración</h1>
            <p>Este panel debería ser solo para root, pero no hay verificación.</p>
            <p>Usuario actual: ${req.session.username || 'No autenticado'} (Rol: ${req.session.rol || 'ninguno'})</p>
            <a href="/dashboard">Volver</a>
        </body>
        </html>
    `);
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Página de login
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - App Vulnerable</title>
            <style>
                body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f0f0; }
                .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
                input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }
                button:hover { background: #0052a3; }
                .info { background: #fff3cd; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 13px; }
                .credentials { background: #e8f4f8; padding: 10px; border-radius: 4px; margin-top: 15px; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2 style="text-align: center;">Login</h2>
                <div class="info">
                    <strong>⚠️ Aplicación Vulnerable</strong><br>
                    Solo para fines educativos de seguridad.
                </div>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Usuario" required>
                    <input type="password" name="password" placeholder="Contraseña" required>
                    <button type="submit">Ingresar</button>
                </form>
                <div class="credentials">
                    <strong>Credenciales de prueba:</strong><br>
                    Root: root / root123<br>
                    Usuario: usuario1 / user123
                </div>
            </div>
        </body>
        </html>
    `);
});

app.listen(PORT, () => {
    console.log(`Aplicación vulnerable corriendo en http://localhost:${PORT}`);
    console.log('Credenciales: root/root123 o usuario1/user123');
});
