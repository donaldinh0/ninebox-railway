// server.js - VERSÃO COMPLETA E ATUALIZADA
const express = require('express');
const http = require('http');
const path = require('path');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Configuração do Banco de Dados
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

db.connect(err => {
    if (err) {
        console.error('Erro fatal ao conectar ao banco de dados:', err.stack);
    } else {
        console.log('Conectado ao banco de dados PostgreSQL com sucesso.');
    }
});

// Configuração do Nodemailer
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false, // true para a porta 465, false para outras como a 587
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuração da Sessão
app.use(session({
    store: new pgSession({
        pool: db,
        tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET || 'uma_chave_secreta_muito_forte',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias
}));

// Servir arquivos estáticos da pasta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// ROTAS DE PÁGINAS PRINCIPAIS
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect(req.session.isAdmin ? '/admin' : '/dashboard');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).send('Usuário ou senha inválidos.');
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.isAdmin = user.isAdmin;
            res.redirect(user.isAdmin ? '/admin' : '/dashboard');
        } else {
            res.status(401).send('Usuário ou senha inválidos.');
        }
    } catch (err) {
        console.error('Erro durante o login:', err);
        res.status(500).send('Erro interno do servidor.');
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Não foi possível fazer logout.');
        res.redirect('/');
    });
});


// ROTAS DA API
app.get('/api/all-scores', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    db.query('SELECT id, username, email, "nineBoxScore", notes FROM users WHERE "isAdmin" = FALSE ORDER BY username ASC', (err, result) => {
        if (err) return res.status(500).send('Erro ao buscar usuários.');
        res.json(result.rows);
    });
});

app.post('/api/update-score', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    const { userId, nineBoxScore, notes } = req.body;
    db.query('UPDATE users SET "nineBoxScore" = $1, notes = $2 WHERE id = $3', [nineBoxScore, notes, userId], (err) => {
        if (err) return res.status(500).send('Erro ao atualizar pontuação.');
        res.status(200).send('Pontuação atualizada com sucesso.');
    });
});

app.post('/api/create-user', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Acesso negado.');
    }
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
        return res.status(400).send('Nome de usuário, e-mail e senha são obrigatórios.');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        await db.query('INSERT INTO users (username, password, email, "isAdmin") VALUES ($1, $2, $3, $4)', [username, hashedPassword, email, false]);
        res.status(201).send('Usuário criado com sucesso!');
    } catch (err) {
        if (err.code === '23505') {
            if (err.constraint === 'users_username_key') return res.status(409).send('Nome de usuário já existe.');
            if (err.constraint === 'users_email_key') return res.status(409).send('Este e-mail já está em uso.');
        }
        console.error('Erro ao criar novo usuário:', err);
        res.status(500).send('Erro ao criar usuário.');
    }
});

app.delete('/api/delete-user/:id', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Acesso negado.');
    const userId = req.params.id;
    db.query('DELETE FROM users WHERE id = $1 AND "isAdmin" = FALSE', [userId], (err) => {
        if (err) return res.status(500).send('Erro ao deletar usuário.');
        res.status(200).send('Usuário deletado com sucesso.');
    });
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(200).send('Se um usuário com este e-mail existir, um link de recuperação foi enviado.');
        }
        const token = crypto.randomBytes(32).toString('hex');
        const expires_at = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos
        await db.query('INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)', [email, token, expires_at]);
        const resetLink = `${process.env.APP_URL}/reset-password.html?token=${token}`;
        await transporter.sendMail({
            from: `"Ninebox App" <${process.env.SMTP_USER}>`,
            to: email,
            subject: 'Recuperação de Senha - Ninebox',
            html: `<p>Olá!</p><p>Clique no link a seguir para redefinir sua senha: <a href="${resetLink}">Redefinir Senha</a></p><p>Este link expira em 15 minutos.</p>`,
        });
        res.status(200).send('Se um usuário com este e-mail existir, um link de recuperação foi enviado.');
    } catch (error) {
        console.error('Erro em forgot-password:', error);
        res.status(500).send('Erro interno do servidor.');
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const resetResult = await db.query('SELECT * FROM password_resets WHERE token = $1 AND expires_at > NOW()', [token]);
        if (resetResult.rows.length === 0) {
            return res.status(400).send('Token inválido ou expirado.');
        }
        const { email } = resetResult.rows[0];
        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await db.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
        await db.query('DELETE FROM password_resets WHERE token = $1', [token]);
        res.status(200).send('Senha alterada com sucesso!');
    } catch (error) {
        console.error('Erro em reset-password:', error);
        res.status(500).send('Erro interno do servidor.');
    }
});

// ROTA PARA O USUÁRIO LOGADO BUSCAR SEUS DADOS
app.get('/api/my-score', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Não autorizado.');
    }
    db.query('SELECT "nineBoxScore", username, notes FROM users WHERE id = $1', [req.session.userId], (err, result) => {
        if (err || result.rows.length === 0) {
            console.error('Erro no DB ao buscar pontuação do usuário:', err);
            return res.status(500).send('Erro ao buscar sua pontuação.');
        }
        res.json(result.rows[0]);
    });
});

// ROTA PARA BUSCAR OS TEXTOS DOS BOXES (definidos pelo admin)
app.get('/api/nine-box-texts', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Não autorizado.');
    }
    db.query('SELECT box_texts FROM users WHERE "isAdmin" = TRUE LIMIT 1', (err, result) => {
        if (err || result.rows.length === 0 || !result.rows[0].box_texts) {
            console.error('Erro ao buscar textos do Nine Box:', err);
            return res.status(500).json({});
        }
        res.json(JSON.parse(result.rows[0].box_texts));
    });
});

// ROTA PARA O ADMIN ATUALIZAR OS TEXTOS DOS BOXES
app.post('/api/update-nine-box-texts', (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Acesso negado.');
    }
    const { texts } = req.body;
    db.query('UPDATE users SET box_texts = $1 WHERE "isAdmin" = TRUE', [JSON.stringify(texts)], (err) => {
        if (err) {
            console.error('Erro ao atualizar os textos do Nine Box:', err);
            return res.status(500).send('Erro ao atualizar os textos.');
        }
        res.status(200).send('Textos atualizados com sucesso.');
    });
});

// ROTA PARA ALTERAR A SENHA A PARTIR DA TELA DE LOGIN
app.post('/api/change-password-login', async (req, res) => {
    const { username, currentPassword, newPassword } = req.body;
    if (!username || !currentPassword || !newPassword) {
        return res.status(400).send('Preencha todos os campos.');
    }
    try {
        const result = await db.query('SELECT id, password FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(404).send('Usuário não encontrado.');
        }
        const user = result.rows[0];
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).send('Senha atual incorreta.');
        }
        const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await db.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, user.id]);
        res.status(200).send('Senha alterada com sucesso!');
    } catch (err) {
        console.error('Erro ao alterar senha:', err);
        res.status(500).send('Erro interno ao tentar alterar a senha.');
    }
});


// Inicia o servidor
server.listen(PORT, () => {
    console.log(`Servidor Nine Box rodando na porta ${PORT}`);
});