/**
 * Rota de Autenticação JWT — POST /api/auth/login
 *
 * Princípios de Segurança Aplicados:
 * 1. Banco de Dados de Usuários:
 *    Credenciais e perfis de acesso consultados na tabela `usuarios` do Supabase / SQLite.
 * 2. Criptografia com Salt e Work Factor (bcrypt):
 *    Senhas nunca em texto claro. Verificação via timing-safe compare com fator de custo 10.
 * 3. Trilha de Auditoria Forense (logs_auditoria):
 *    Tentativas de login inválidas, usuários inexistentes e sucessos são registrados.
 * 4. Logs Coloridos em Tempo Real:
 *    Saída visual detalhada no terminal preservada com prefixos [SECURITY], [WARN], [SUCCESS].
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const router  = express.Router();
const logger  = require('../logger');
const db      = require('../database');
const { SECRET_KEY, EXPIRES_IN } = require('../middlewares/auth');

// Usuários de demonstração em fallback (garante funcionamento mesmo antes de rodar o SQL)
const FALLBACK_USERS = [
    {
        id: 1,
        username: 'admin',
        password_hash: '$2b$10$aQXpxtlzIQ0eQRB.JEZJOe0JcOF/VZXeieG6yyvrtuIvuni7aajly',
        role: 'administrador',
        nome: 'Administrador do Sistema'
    },
    {
        id: 2,
        username: 'gerente',
        password_hash: '$2b$10$cV1CO5x6MmWE7EXJKdyc7uvdvEqnRgkcdk7NCvDVJTmUlrm0LATuq',
        role: 'gerente',
        nome: 'Gerente da Cafeteria'
    }
];

/**
 * POST /api/auth/login
 * Autentica o operador via tabela `usuarios` e emite JWT.
 */
router.post('/login', async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const { usuario, senha } = req.body;

    // 1. Validação de presença dos campos
    if (!usuario || !senha) {
        logger.warn('Tentativa de login com campos vazios', { ip });
        db.logsAuditoria.insert({ nivel: 'WARN', mensagem: 'Tentativa de login com campos vazios', ip }).catch(() => {});
        return res.status(400).json({
            success: false,
            error: 'Usuário e senha são obrigatórios.',
            code: 'AUTH_MISSING_CREDENTIALS'
        });
    }

    // 2. Sanitização básica (evita payloads absurdos)
    if (typeof usuario !== 'string' || usuario.length > 50 ||
        typeof senha !== 'string'   || senha.length > 100) {
        logger.security('Tentativa de login com payload suspeito (tamanho anormal)', {
            ip,
            tamanhoUsuario: String(usuario).length,
            tamanhoPwd: String(senha).length
        });
        db.logsAuditoria.insert({ nivel: 'SECURITY', mensagem: 'Tentativa de login com payload de tamanho anormal', ip }).catch(() => {});
        return res.status(400).json({
            success: false,
            error: 'Dados de login inválidos.',
            code: 'AUTH_INVALID_INPUT'
        });
    }

    // 3. Busca o usuário no banco de dados (tabela usuarios no Supabase ou SQLite)
    let user = null;
    try {
        user = await db.usuarios.getByUsername(usuario);
    } catch (err) {
        logger.warn('Aviso ao consultar tabela usuarios no banco:', { detalhe: err.message });
    }

    // Fallback se a tabela ainda não estiver criada no Supabase
    if (!user) {
        user = FALLBACK_USERS.find(u => u.username.toLowerCase() === usuario.toLowerCase().trim());
    }

    if (!user) {
        logger.security('Tentativa de login com usuário inexistente', { ip, usuario });
        db.logsAuditoria.insert({
            nivel: 'SECURITY',
            mensagem: 'Tentativa de login com usuário inexistente',
            detalhes: { usuario_tentado: usuario },
            ip,
            operador: usuario
        }).catch(() => {});

        // Resposta genérica (não revela se o usuário existe — defesa contra enumeração)
        return res.status(401).json({
            success: false,
            error: 'Usuário ou senha incorretos.',
            code: 'AUTH_INVALID_CREDENTIALS'
        });
    }

    // 4. Verificação da senha com bcrypt (timing-safe comparison)
    const passwordHash = user.password_hash || user.passwordHash;
    const senhaValida = await bcrypt.compare(senha, passwordHash);

    if (!senhaValida) {
        logger.security('Tentativa de login com senha incorreta', {
            ip,
            usuario: user.username
        });
        db.logsAuditoria.insert({
            nivel: 'SECURITY',
            mensagem: 'Tentativa de login com senha incorreta',
            detalhes: { usuario: user.username },
            ip,
            operador: user.username
        }).catch(() => {});

        return res.status(401).json({
            success: false,
            error: 'Usuário ou senha incorretos.',
            code: 'AUTH_INVALID_CREDENTIALS'
        });
    }

    // 5. Gera o JWT com payload mínimo necessário
    const payload = {
        sub:     user.id,
        usuario: user.username,
        role:    user.role,
        nome:    user.nome,
        iat:     Math.floor(Date.now() / 1000)
    };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: EXPIRES_IN });

    logger.success('Login realizado com sucesso', {
        usuario: user.username,
        perfil: user.role,
        ip,
        expira: EXPIRES_IN
    });

    db.logsAuditoria.insert({
        nivel: 'SUCCESS',
        mensagem: 'Login realizado com sucesso',
        detalhes: { perfil: user.role, expira: EXPIRES_IN },
        ip,
        operador: user.username
    }).catch(() => {});

    return res.status(200).json({
        success: true,
        message: `Bem-vindo, ${user.nome}!`,
        token,
        usuario: {
            id:      user.id,
            usuario: user.username,
            nome:    user.nome,
            perfil:  user.role
        },
        expiraEm: EXPIRES_IN
    });
});

/**
 * POST /api/auth/logout
 * Auditoria de logout
 */
router.post('/logout', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const authHeader = req.headers['authorization'];
    let usuario = 'desconhecido';

    if (authHeader) {
        try {
            const jwt_lib = require('jsonwebtoken');
            const decoded = jwt_lib.decode(authHeader.split(' ')[1]);
            if (decoded) usuario = decoded.usuario;
        } catch (_) {}
    }

    logger.info('Logout registrado', { usuario, ip });
    db.logsAuditoria.insert({
        nivel: 'INFO',
        mensagem: 'Logout registrado pelo usuário',
        ip,
        operador: usuario
    }).catch(() => {});

    return res.status(200).json({
        success: true,
        message: 'Logout registrado. Remova o token do armazenamento local.'
    });
});

module.exports = router;
