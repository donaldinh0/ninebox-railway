// server.js - Versão para PostgreSQL
const express = require('express');
const http = require('http');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg'); // <-- Mudança: Importa o driver do Postgres

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Configuração da Conexão com o Postgres usando a DATABASE_URL da Railway
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necessário para conexões em ambientes como a Railway
    }
});

// Função para criar a tabela se ela não existir
async function setupDatabase() {
    const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        nineBoxScore INTEGER DEFAULT 0,
        isAdmin BOOLEAN DEFAULT FALSE,
        notes TEXT DEFAULT ''
    );`;
    
    try {
        await pool.query(createTableQuery);
        console.log('Tabela users verificada/criada.');
        
        // Criar usuário Admin inicial, se não existir
        const adminUsername = 'admin';
        const adminPassword = 'adminpassword';
        
        const res = await pool.query('SELECT id FROM users WHERE username = $1', [adminUsername]);
        if (res.rowCount === 0) {
            const hashedPassword = await bcrypt.hash(adminPassword, SALT_ROUNDS);
            await pool.query('INSERT INTO users (username, password, isAdmin) VALUES ($1, $2, TRUE)', [adminUsername, hashedPassword]);
            console.log('Usuário Admin inicial criado.');
        }
    } catch (err) {
        console.error('Erro ao configurar o banco de dados:', err.stack);
    }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'SUA_CHAVE_SECRETA_NINEBOX_AQUI',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: 'auto' }
}));

app.use(express.static('public'));

// ---- ROTAS DE PÁGINAS ----
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard.html');
    } else {
        res.sendFile(__dirname + '/public/login.html');
    }
});

// As rotas /dashboard e /admin agora são servidas automaticamente pelo express.static
// Se precisar de lógica de proteção, mantemos as rotas:
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/login.html');
    res.sendFile(__dirname + '/public/dashboard.html');
});

app.get('/admin', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    res.sendFile(__dirname + '/public/admin.html');
});


// ---- ROTAS DE API ----
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).send('Usuário ou senha inválidos.');
        }

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.isAdmin = user.isadmin; // 'isadmin' em minúsculas
            
            if (user.isadmin) {
                res.redirect('/admin');
            } else {
                res.redirect('/dashboard');
            }
        } else {
            res.status(400).send('Usuário ou senha inválidos.');
        }
    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).send('Erro interno do servidor.');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Não foi possível fazer logout.');
        }
        res.redirect('/login.html');
    });
});

app.post('/api/change-password-login', async (req, res) => {
    const { username, currentPassword, newPassword } = req.body;
    if (!username || !currentPassword || !newPassword) {
        return res.status(400).send('Preencha todos os campos.');
    }
    try {
        const result = await pool.query('SELECT id, password FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(400).send('Usuário não encontrado.');

        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) return res.status(400).send('Senha atual incorreta.');

        const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, user.id]);
        res.status(200).send('Senha alterada com sucesso!');
    } catch (err) {
        console.error('Erro ao alterar senha:', err);
        res.status(500).send('Erro ao atualizar a senha.');
    }
});

app.get('/api/my-score', async (req, res) => {
    if (!req.session.userId) return res.status(401).send('Não autorizado.');
    try {
        const result = await pool.query('SELECT "nineBoxScore", username, notes FROM users WHERE id = $1', [req.session.userId]);
        const data = result.rows[0];
        if (!data) return res.status(404).send('Usuário não encontrado.');
        res.json({ nineBoxScore: data.nineBoxScore, username: data.username, notes: data.notes });
    } catch (err) {
        console.error('Erro ao buscar pontuação:', err);
        res.status(500).send('Erro ao buscar pontuação.');
    }
});

app.get('/api/all-scores', async (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    try {
        const result = await pool.query('SELECT id, username, "nineBoxScore", notes FROM users WHERE "isAdmin" = FALSE');
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao buscar todos os usuários:', err);
        res.status(500).send('Erro ao buscar usuários.');
    }
});

app.post('/api/update-score', async (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    const { userId, nineBoxScore, notes } = req.body;
    try {
        await pool.query('UPDATE users SET "nineBoxScore" = $1, notes = $2 WHERE id = $3', [nineBoxScore, notes, userId]);
        res.status(200).send('Pontuação e observações atualizadas com sucesso.');
    } catch (err) {
        console.error('Erro ao atualizar pontuação:', err);
        res.status(500).send('Erro ao atualizar pontuação.');
    }
});

app.post('/api/create-user', async (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Nome de usuário e senha são obrigatórios.');
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        await pool.query('INSERT INTO users (username, password, "isAdmin") VALUES ($1, $2, FALSE)', [username, hashedPassword]);
        res.status(201).send('Usuário criado com sucesso!');
    } catch (err) {
        if (err.code === '23505') { // Código de erro do Postgres para violação de constraint UNIQUE
            return res.status(409).send('Nome de usuário já existe.');
        }
        console.error('Erro ao criar novo usuário:', err);
        res.status(500).send('Erro ao criar usuário.');
    }
});

app.delete('/api/delete-user/:id', async (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    const userId = req.params.id;
    try {
        await pool.query('DELETE FROM users WHERE id = $1 AND "isAdmin" = FALSE', [userId]);
        res.status(200).send('Usuário deletado com sucesso.');
    } catch (err) {
        console.error('Erro ao deletar usuário:', err);
        res.status(500).send('Erro ao deletar usuário.');
    }
});

// Inicia o servidor e o setup do banco de dados
server.listen(PORT, () => {
    console.log(`Servidor Nine Box rodando em http://localhost:${PORT}`);
    setupDatabase();
});