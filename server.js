/**
 * ============================================================
 * CAFÉ ARTISANAL — SERVIDOR NODE.JS COM BACK-END SEGURO
 * Disciplina: Segurança em Sistemas da Informação (FICR)
 * ============================================================
 *
 * Artefatos de Segurança Implementados:
 *
 * 1. LOGS DETALHADOS  → morgan (HTTP) + logger customizado (eventos de segurança)
 * 2. SQL INJECTION     → better-sqlite3 com Prepared Statements em todas as queries
 * 3. RATE LIMITING     → express-rate-limit (login: 5/15min | api: 150/15min | escrita: 20/10min)
 * 4. JWT AUTH          → jsonwebtoken + bcryptjs para rotas de escrita e deleção
 * 5. HELMET            → 15+ cabeçalhos HTTP de segurança (CSP, HSTS, X-Frame, etc.)
 */

const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const morgan     = require('morgan');
const helmet     = require('helmet');

const logger     = require('./src/logger');
const { queries } = require('./src/database');
const { loginLimiter, apiLimiter, writeLimiter } = require('./src/middlewares/rateLimiter');

// Rotas modularizadas
const authRoutes    = require('./src/routes/auth');
const pessoasRoutes = require('./src/routes/pessoas');
const produtosRoutes = require('./src/routes/produtos');

const app  = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 1. HELMET — Cabeçalhos HTTP de Segurança Avançados
// ============================================================
// Por que Helmet:
// Substitui os 3 cabeçalhos manuais por ~15 políticas de segurança HTTP
// que protegem contra Clickjacking, MIME Sniffing, XSS externo,
// ataques de downgrade HTTPS (HSTS), vazamento de origem via Referer, etc.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc:   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'cdnjs.cloudflare.com'],
            fontSrc:    ["'self'", 'fonts.gstatic.com', 'cdnjs.cloudflare.com'],
            scriptSrc:  ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com'],
            imgSrc:     ["'self'", 'data:'],
            connectSrc: ["'self'"],
        }
    },
    crossOriginEmbedderPolicy: false // Necessário para FontAwesome CDN
}));

// ============================================================
// 2. MORGAN — Logs de Requisições HTTP
// ============================================================
// Por que Morgan:
// Gera uma linha de log para CADA requisição HTTP recebida,
// incluindo método, rota, status, tempo de resposta e IP.
// Essencial para auditoria, detecção de anomalias e debugging.
app.use(morgan(':method :url :status :response-time ms | IP: :remote-addr', {
    stream: {
        write: (message) => logger.info(`HTTP ${message.trim()}`)
    }
}));

// ============================================================
// 3. MIDDLEWARES ESSENCIAIS
// ============================================================
app.use(cors({
    origin: [`http://localhost:${PORT}`],
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Limite de payload a 50kb — prevenção de DoS por payload gigante
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// 4. RATE LIMITING — Aplicado às rotas da API
// ============================================================
// Por que Rate Limiting:
// Sem limitação, a API é vulnerável a Força Bruta, DDoS e Scraping.
// Limitadores com janelas de tempo diferentes para cada tipo de operação.

// Limitador geral para toda a API
app.use('/api', apiLimiter);

// Limitador específico e mais restrito para operações de escrita
app.use('/api/pessoas', writeLimiter);
app.use('/api/produtos', writeLimiter);

// ============================================================
// 5. ROTAS DE AUTENTICAÇÃO (com Rate Limiting de Força Bruta)
// ============================================================
// Por que loginLimiter especial:
// Login é o principal alvo de Força Bruta. Apenas 5 tentativas por 15 min.
app.use('/api/auth', loginLimiter, authRoutes);

// ============================================================
// 6. ROTAS DA API — CRUD com SQLite e Logs
// ============================================================
// Rotas públicas: GET /api/pessoas e GET /api/produtos
// Rotas protegidas: POST e DELETE exigem JWT válido (verificado internamente nas rotas)
app.use('/api/pessoas', pessoasRoutes);
app.use('/api/produtos', produtosRoutes);

// ============================================================
// 7. ROTA DE STATS (pública, com log)
// ============================================================
app.get('/api/stats', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    try {
        const totalPessoas  = queries.countPessoas.get().total;
        const totalProdutos = queries.countProdutos.get().total;
        const totalEstoque  = queries.sumEstoque.get().total;

        logger.info('Stats do dashboard consultadas', { ip, totalPessoas, totalProdutos, totalEstoque });

        res.json({ totalPessoas, totalProdutos, totalEstoque });
    } catch (err) {
        logger.error('Erro ao consultar stats', { ip, detalhe: err.message });
        res.status(500).json({ success: false, error: 'Erro interno.' });
    }
});

// ============================================================
// 8. ROTA DE STATUS DA SEGURANÇA (informativa)
// ============================================================
app.get('/api/security-info', (req, res) => {
    res.json({
        success: true,
        artefatos: [
            { nome: 'Logs Detalhados',  tecnologia: 'morgan + logger customizado', status: 'ATIVO' },
            { nome: 'SQL Injection',    tecnologia: 'better-sqlite3 Prepared Statements', status: 'ATIVO' },
            { nome: 'Rate Limiting',    tecnologia: 'express-rate-limit', status: 'ATIVO',
              limites: { login: '5/15min', api: '150/15min', escrita: '20/10min' } },
            { nome: 'Autenticação JWT', tecnologia: 'jsonwebtoken + bcryptjs', status: 'ATIVO',
              expiracao: '2h', rotas_protegidas: ['POST /api/pessoas', 'DELETE /api/pessoas/:id', 'POST /api/produtos', 'DELETE /api/produtos/:id'] },
            { nome: 'Helmet.js',        tecnologia: 'helmet', status: 'ATIVO',
              cabecalhos: ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Referrer-Policy'] }
        ]
    });
});

// ============================================================
// 9. HANDLER GLOBAL DE ERROS
// ============================================================
app.use((err, req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    logger.error('Erro não tratado no servidor', {
        ip,
        rota: req.originalUrl,
        metodo: req.method,
        detalhe: err.message
    });
    res.status(500).json({ success: false, error: 'Erro interno do servidor.' });
});

// ============================================================
// INICIALIZAÇÃO DO SERVIDOR
// ============================================================
app.listen(PORT, () => {
    logger.banner();
    console.log('');
    logger.success(`Servidor rodando em http://localhost:${PORT}`);
    console.log('');
    logger.info('Artefatos de Segurança Ativos:', {
        Helmet: 'ON', Morgan: 'ON', RateLimit: 'ON', JWT: 'ON', SQLite_PreparedStmts: 'ON'
    });
    console.log('');
    logger.warn('CREDENCIAIS DE ACESSO (DEMO ACADÊMICO)');
    console.log('         admin   / cafe@2025       (Administrador)');
    console.log('         gerente / espresso123     (Gerente)');
    console.log('');
});
