// server.js - Servidor principal del sistema de citas UPIICSA
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'upiicsa_citas_secret_key_2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de la base de datos
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '$051513icy3c1',
    database: process.env.DB_NAME || 'citas_upiicsa',
    port: process.env.DB_PORT || 3306
};

// Pool de conexiones a la base de datos
const pool = mysql.createPool({
    ...dbConfig,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Middleware para verificar roles
const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.tipo_usuario)) {
            return res.status(403).json({ error: 'No tiene permisos para esta acción' });
        }
        next();
    };
};

// ============ RUTAS DE AUTENTICACIÓN ============

// Registro de usuarios
app.post('/api/register', async (req, res) => {
    try {
        const { boleta, nombre, apellidos, email, password, telefono, carrera, semestre, tipo_usuario = 'alumno' } = req.body;

        // Validaciones básicas
        if (!nombre || !apellidos || !email || !password) {
            return res.status(400).json({ error: 'Campos obligatorios faltantes' });
        }

        if (tipo_usuario === 'alumno' && !boleta) {
            return res.status(400).json({ error: 'La boleta es obligatoria para estudiantes' });
        }

        // Verificar si el usuario ya existe
        const [existing] = await pool.execute(
            'SELECT id FROM usuarios WHERE email = ? OR boleta = ?',
            [email, boleta]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }

        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar usuario
        const [result] = await pool.execute(
            `INSERT INTO usuarios (boleta, nombre, apellidos, email, password, telefono, carrera, semestre, tipo_usuario) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [boleta, nombre, apellidos, email, hashedPassword, telefono, carrera, semestre, tipo_usuario]
        );

        res.status(201).json({
            message: 'Usuario registrado exitosamente',
            userId: result.insertId
        });

    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Inicio de sesión
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
        }

        // Buscar usuario
        const [users] = await pool.execute(
            'SELECT id, nombre, apellidos, email, password, boleta, tipo_usuario, activo FROM usuarios WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const user = users[0];

        if (!user.activo) {
            return res.status(401).json({ error: 'Cuenta desactivada' });
        }

        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Generar token JWT
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                tipo_usuario: user.tipo_usuario,
                nombre: user.nombre,
                apellidos: user.apellidos
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Inicio de sesión exitoso',
            token,
            user: {
                id: user.id,
                nombre: user.nombre,
                apellidos: user.apellidos,
                email: user.email,
                boleta: user.boleta,
                tipo_usuario: user.tipo_usuario
            }
        });

    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============ RUTAS DE CITAS ============

// Obtener citas del usuario autenticado
app.get('/api/citas', authenticateToken, async (req, res) => {
    try {
        let query = '';
        let params = [];

        if (req.user.tipo_usuario === 'alumno') {
            query = `
                SELECT c.*, 
                       p.nombre as psicologo_nombre, 
                       p.apellidos as psicologo_apellidos,
                       ps.especialidad,
                       ps.consultorio
                FROM citas c
                JOIN usuarios p ON c.psicologo_id = p.id
                LEFT JOIN psicologos ps ON p.id = ps.usuario_id
                WHERE c.alumno_id = ?
                ORDER BY c.fecha_cita DESC, c.hora_inicio DESC
            `;
            params = [req.user.id];
        } else if (req.user.tipo_usuario === 'psicologo') {
            query = `
                SELECT c.*, 
                       a.nombre as alumno_nombre, 
                       a.apellidos as alumno_apellidos,
                       a.boleta,
                       a.carrera,
                       a.semestre
                FROM citas c
                JOIN usuarios a ON c.alumno_id = a.id
                WHERE c.psicologo_id = ?
                ORDER BY c.fecha_cita DESC, c.hora_inicio DESC
            `;
            params = [req.user.id];
        } else {
            // Admin ve todas las citas
            query = `
                SELECT c.*, 
                       a.nombre as alumno_nombre, 
                       a.apellidos as alumno_apellidos,
                       a.boleta,
                       p.nombre as psicologo_nombre, 
                       p.apellidos as psicologo_apellidos
                FROM citas c
                JOIN usuarios a ON c.alumno_id = a.id
                JOIN usuarios p ON c.psicologo_id = p.id
                ORDER BY c.fecha_cita DESC, c.hora_inicio DESC
            `;
        }

        const [citas] = await pool.execute(query, params);
        res.json(citas);

    } catch (error) {
        console.error('Error obteniendo citas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Crear nueva cita (solo alumnos)
app.post('/api/citas', authenticateToken, authorizeRole(['alumno']), async (req, res) => {
    try {
        const { psicologo_id, fecha_cita, hora_inicio, motivo, tipo_cita = 'primera_vez', modalidad = 'presencial' } = req.body;

        if (!psicologo_id || !fecha_cita || !hora_inicio) {
            return res.status(400).json({ error: 'Datos obligatorios faltantes' });
        }

        // Calcular hora_fin (60 minutos después)
        const [hours, minutes] = hora_inicio.split(':');
        const startTime = new Date();
        startTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        const endTime = new Date(startTime.getTime() + 60 * 60 * 1000);
        const hora_fin = endTime.toTimeString().substring(0, 5);

        // Verificar disponibilidad
        const [conflictos] = await pool.execute(
            `SELECT id FROM citas 
             WHERE psicologo_id = ? AND fecha_cita = ? 
             AND ((hora_inicio <= ? AND hora_fin > ?) OR (hora_inicio < ? AND hora_fin >= ?))
             AND estado NOT IN ('cancelada')`,
            [psicologo_id, fecha_cita, hora_inicio, hora_inicio, hora_fin, hora_fin]
        );

        if (conflictos.length > 0) {
            return res.status(400).json({ error: 'El horario no está disponible' });
        }

        // Crear cita
        const [result] = await pool.execute(
            `INSERT INTO citas (alumno_id, psicologo_id, fecha_cita, hora_inicio, hora_fin, motivo, tipo_cita, modalidad) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, psicologo_id, fecha_cita, hora_inicio, hora_fin, motivo, tipo_cita, modalidad]
        );

        // Crear notificación para el psicólogo
        await pool.execute(
            `INSERT INTO notificaciones (usuario_id, titulo, mensaje, tipo) 
             VALUES (?, ?, ?, ?)`,
            [
                psicologo_id,
                'Nueva cita solicitada',
                `${req.user.nombre} ${req.user.apellidos} ha solicitado una cita para el ${fecha_cita} a las ${hora_inicio}`,
                'cita_confirmada'
            ]
        );

        res.status(201).json({
            message: 'Cita creada exitosamente',
            citaId: result.insertId
        });

    } catch (error) {
        console.error('Error creando cita:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Actualizar estado de cita (psicólogos y admin)
app.put('/api/citas/:id', authenticateToken, authorizeRole(['psicologo', 'admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { estado, observaciones } = req.body;

        const estadosValidos = ['pendiente', 'confirmada', 'en_curso', 'completada', 'cancelada', 'no_asistio'];
        if (!estadosValidos.includes(estado)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }

        await pool.execute(
            'UPDATE citas SET estado = ?, observaciones = ? WHERE id = ?',
            [estado, observaciones, id]
        );

        res.json({ message: 'Cita actualizada exitosamente' });

    } catch (error) {
        console.error('Error actualizando cita:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============ RUTAS DE PSICÓLOGOS ============

// Obtener lista de psicólogos disponibles
app.get('/api/psicologos', authenticateToken, async (req, res) => {
    try {
        const [psicologos] = await pool.execute(
            `SELECT u.id, u.nombre, u.apellidos, u.email, u.telefono,
                    p.especialidad, p.consultorio, p.biografia, p.horario_inicio, p.horario_fin
             FROM usuarios u
             JOIN psicologos p ON u.id = p.usuario_id
             WHERE u.tipo_usuario = 'psicologo' AND u.activo = TRUE
             ORDER BY u.nombre, u.apellidos`
        );

        res.json(psicologos);

    } catch (error) {
        console.error('Error obteniendo psicólogos:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Obtener disponibilidad de un psicólogo
app.get('/api/psicologos/:id/disponibilidad', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const fecha_inicio = req.query.fecha_inicio || new Date().toISOString().split('T')[0];
        const fecha_fin = req.query.fecha_fin || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

        const [disponibilidad] = await pool.execute(
            `SELECT fecha, hora_inicio, hora_fin, disponible, motivo_no_disponible
             FROM disponibilidad 
             WHERE psicologo_id = ? AND fecha BETWEEN ? AND ?
             ORDER BY fecha, hora_inicio`,
            [id, fecha_inicio, fecha_fin]
        );

        res.json(disponibilidad);

    } catch (error) {
        console.error('Error obteniendo disponibilidad:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============ RUTAS DE NOTIFICACIONES ============

// Obtener notificaciones del usuario
app.get('/api/notificaciones', authenticateToken, async (req, res) => {
    try {
        const [notificaciones] = await pool.execute(
            'SELECT * FROM notificaciones WHERE usuario_id = ? ORDER BY fecha_envio DESC LIMIT 50',
            [req.user.id]
        );

        res.json(notificaciones);

    } catch (error) {
        console.error('Error obteniendo notificaciones:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Marcar notificación como leída
app.put('/api/notificaciones/:id/leer', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        await pool.execute(
            'UPDATE notificaciones SET leida = TRUE WHERE id = ? AND usuario_id = ?',
            [id, req.user.id]
        );

        res.json({ message: 'Notificación marcada como leída' });

    } catch (error) {
        console.error('Error actualizando notificación:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============ RUTAS DE DASHBOARD ============

// Dashboard para alumnos
app.get('/api/dashboard/alumno', authenticateToken, authorizeRole(['alumno']), async (req, res) => {
    try {
        // Próxima cita
        const [proximaCita] = await pool.execute(
            `SELECT c.*, p.nombre as psicologo_nombre, p.apellidos as psicologo_apellidos, ps.consultorio
             FROM citas c
             JOIN usuarios p ON c.psicologo_id = p.id
             LEFT JOIN psicologos ps ON p.id = ps.usuario_id
             WHERE c.alumno_id = ? AND c.fecha_cita >= CURDATE() AND c.estado IN ('pendiente', 'confirmada')
             ORDER BY c.fecha_cita, c.hora_inicio
             LIMIT 1`,
            [req.user.id]
        );

        // Estadísticas
        const [stats] = await pool.execute(
            `SELECT 
                COUNT(*) as total_citas,
                SUM(CASE WHEN estado = 'completada' THEN 1 ELSE 0 END) as citas_completadas,
                SUM(CASE WHEN estado = 'cancelada' THEN 1 ELSE 0 END) as citas_canceladas,
                SUM(CASE WHEN estado IN ('pendiente', 'confirmada') THEN 1 ELSE 0 END) as citas_pendientes
             FROM citas WHERE alumno_id = ?`,
            [req.user.id]
        );

        // Notificaciones no leídas
        const [notificaciones] = await pool.execute(
            'SELECT COUNT(*) as no_leidas FROM notificaciones WHERE usuario_id = ? AND leida = FALSE',
            [req.user.id]
        );

        res.json({
            proximaCita: proximaCita[0] || null,
            estadisticas: stats[0],
            notificacionesNoLeidas: notificaciones[0].no_leidas
        });

    } catch (error) {
        console.error('Error en dashboard alumno:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ============ RUTAS ESTÁTICAS ============

// Servir archivos estáticos
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/citas', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'citas.html'));
});

app.get('/perfil', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'perfil.html'));
});

// ============ MIDDLEWARE DE MANEJO DE ERRORES ============

app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ============ INICIAR SERVIDOR ============

app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    console.log(`📱 Accede a la aplicación en: http://localhost:${PORT}`);
    console.log(`🏥 Sistema de Citas Psicológicas UPIICSA`);
});

// Manejo de cierre graceful
process.on('SIGTERM', async () => {
    console.log('Cerrando servidor...');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('Cerrando servidor...');
    await pool.end();
    process.exit(0);
});