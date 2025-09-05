// server.js - VERSÃO FINAL E CORRIGIDA
const express = require('express');
const http = require('http');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session); // Correção da sessão

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
        // Verificação e criação da tabela e do admin
        db.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            "nineBoxScore" INTEGER DEFAULT 0,
            "isAdmin" BOOLEAN DEFAULT FALSE,
            notes TEXT DEFAULT '',
            box_texts TEXT DEFAULT ''
        )`, (err) => {
            if (err) {
                console.error('Erro ao criar tabela users:', err.message);
            } else {
                console.log('Tabela users verificada/criada.');
                const adminUsername = 'admin';
                const adminPassword = 'adminpassword';
                db.query('SELECT id FROM users WHERE username = $1', [adminUsername], async (err, result) => {
                    if (err) {
                        console.error('Erro ao verificar Admin:', err.message);
                    }
                    if (result.rows.length === 0) {
                        const hashedPassword = await bcrypt.hash(adminPassword, SALT_ROUNDS);
                        const initialBoxTexts = JSON.stringify({
                            '1': 'Descrição B1', '2': 'Descrição B2', '3': 'Descrição B3',
                            '4': 'Descrição M1', '5': 'Descrição M2', '6': 'Descrição M3',
                            '7': 'Descrição A1', '8': 'Descrição A2', '9': 'Descrição A3'
                        });
                        db.query('INSERT INTO users (username, password, "isAdmin", box_texts) VALUES ($1, $2, $3, $4)', [adminUsername, hashedPassword, true, initialBoxTexts], (err) => {
                            if (err) {
                                console.error('Erro ao criar Admin:', err.message);
                            } else {
                                console.log('Usuário Admin inicial criado.');
                            }
                        });
                    }
                });
            }
        });
    }
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuração da Sessão (Corrigida para Produção)
app.use(session({
    store: new pgSession({
        pool: db,                // Usa a conexão do banco de dados
        tableName: 'session'     // Nome da tabela para salvar as sessões
    }),
    secret: process.env.SESSION_SECRET || 'uma_chave_secreta_muito_forte', // Use uma variável de ambiente para isso
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias
}));

// Servir arquivos estáticos da pasta 'public'
app.use(express.static('public'));

// Rotas
app.get('/', (req, res) => {
    if (req.session.userId) {
        // Redireciona com base no status de admin já salvo na sessão
        if (req.session.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        res.sendFile(__dirname + '/public/login.html');
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
            // Salva os dados na sessão
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.isAdmin = user.isAdmin;

            // Redireciona com base no dado recém-buscado
            if (user.isAdmin === true) {
                res.redirect('/admin');
            } else {
                res.redirect('/dashboard');
            }
        } else {
            res.status(401).send('Usuário ou senha inválidos.');
        }
    } catch (err) {
        console.error('Erro durante o login:', err);
        res.status(500).send('Erro interno do servidor.');
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(__dirname + '/public/dashboard.html');
});

app.get('/admin', (req, res) => {
    if (!req.session.isAdmin) { // Checagem mais simples e segura
        return res.status(403).send('Acesso negado. Você não é um administrador.');
    }
    res.sendFile(__dirname + '/public/admin.html');
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Não foi possível fazer logout.');
        }
        res.redirect('/');
    });
});

// Rotas de API (mantidas como antes, mas não listadas aqui para brevidade)
// ... cole aqui todas as suas rotas /api/ que já funcionavam ...
// Se precisar, eu as envio novamente.
// R O T A S   D A   A P I
// ==============================================

// API para um usuário (logado ou não) alterar a própria senha
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
// API para o admin buscar todos os usuários (exceto ele mesmo)
app.get('/api/all-scores', (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Acesso negado.');
    }
    db.query('SELECT id, username, "nineBoxScore", notes FROM users WHERE "isAdmin" = FALSE ORDER BY username ASC', (err, result) => {
        if (err) {
            console.error('Erro ao buscar usuários:', err);
            return res.status(500).send('Erro ao buscar usuários.');
        }
        res.json(result.rows);
    });
});

// API para o admin atualizar a pontuação e notas de um usuário
app.post('/api/update-score', (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Acesso negado.');
    }
    const { userId, nineBoxScore, notes } = req.body;
    db.query('UPDATE users SET "nineBoxScore" = $1, notes = $2 WHERE id = $3 AND "isAdmin" = FALSE', [nineBoxScore, notes, userId], (err) => {
        if (err) {
            console.error('Erro ao atualizar pontuação:', err);
            return res.status(500).send('Erro ao atualizar pontuação.');
        }
        res.status(200).send('Pontuação e observações atualizadas com sucesso.');
    });
});

// API para o admin criar um novo usuário
app.post('/api/create-user', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Acesso negado.');
    }
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Nome de usuário and senha são obrigatórios.');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        await db.query('INSERT INTO users (username, password, "isAdmin") VALUES ($1, $2, $3)', [username, hashedPassword, false]);
        res.status(201).send('Usuário criado com sucesso!');
    } catch (err) {
        if (err.code === '23505') { // Código de erro para violação de constraint 'unique'
            return res.status(409).send('Nome de usuário já existe.');
        }
        console.error('Erro ao criar novo usuário:', err);
        res.status(500).send('Erro ao criar usuário.');
    }
});

// API para o admin deletar um usuário
app.delete('/api/delete-user/:id', (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Acesso negado.');
    }
    const userId = req.params.id;
    db.query('DELETE FROM users WHERE id = $1 AND "isAdmin" = FALSE', [userId], (err, result) => {
        if (err) {
            console.error('Erro ao deletar usuário:', err);
            return res.status(500).send('Erro ao deletar usuário.');
        }
        if (result.rowCount === 0) {
            return res.status(404).send('Usuário não encontrado ou já deletado.');
        }
        res.status(200).send('Usuário deletado com sucesso.');
    });
});

// API para o usuário logado buscar sua própria pontuação e notas
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

// API para buscar os textos dos boxes do Nine Box (definidos pelo admin)
app.get('/api/nine-box-texts', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Não autorizado.');
    }
    db.query('SELECT box_texts FROM users WHERE "isAdmin" = TRUE LIMIT 1', (err, result) => {
        if (err || result.rows.length === 0 || !result.rows[0].box_texts) {
            console.error('Erro ao buscar textos do Nine Box:', err);
            // Retorna um objeto vazio como fallback para não quebrar o frontend
            return res.status(500).json({});
        }
        res.json(JSON.parse(result.rows[0].box_texts));
    });
});

// API para o admin atualizar os textos dos boxes
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




// Inicia o servidor
server.listen(PORT, () => {
    console.log(`Servidor Nine Box rodando na porta ${PORT}`);
});