/**
 * Rota de Autenticação JWT — POST /api/auth/login
 *
 * Por que bcryptjs para as senhas:
 * Senhas nunca devem ser armazenadas em texto plano. bcrypt aplica
 * uma função de hash com salt aleatório e fator de custo (work factor),
 * tornando ataques de dicionário e rainbow tables computacionalmente inviáveis.
 * Para fins acadêmicos, os usuários são fixos no código, mas o processo
 * de verificação com bcrypt é idêntico ao de um banco de dados real.
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const router  = express.Router();
const logger  = require('../logger');
const { SECRET_KEY, EXPIRES_IN } = require('../middlewares/auth');

/**
 * Usuários da cafeteria (em produção, estariam no banco de dados com hash bcrypt).
 * As senhas já estão armazenadas como hash bcrypt (nunca em texto plano).
 *
 * Credenciais de acesso:
 *   admin   / cafe@2025
 *   gerente / espresso123
 */
const USERS = [
    {
        id: 1,
        username: 'admin',
        // Hash bcrypt de 'cafe@2025' com salt rounds = 10
        passwordHash: '$2b$10$aQXpxtlzIQ0eQRB.JEZJOe0JcOF/VZXeieG6yyvrtuIvuni7aajly',
        role: 'administrador',
        nome: 'Administrador do Sistema'
    },
    {
        id: 2,
        username: 'gerente',
        // Hash bcrypt de 'espresso123' com salt rounds = 10
        passwordHash: '$2b$10$cV1CO5x6MmWE7EXJKdyc7uvdvEqnRgkcdk7NCvDVJTmUlrm0LATuq',
        role: 'gerente',
        nome: 'Gerente da Cafeteria'
    }
];

/**
 * POST /api/auth/login
 * Autentica o usuário e retorna um JWT válido por 2 horas.
 * Rate Limiting: máximo de 5 tentativas por 15 minutos (aplicado em server.js)
 */
router.post('/login', async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const { usuario, senha } = req.body;

    // 1. Validação de presença dos campos
    if (!usuario || !senha) {
        logger.warn('Tentativa de login com campos vazios', { ip });
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
        return res.status(400).json({
            success: false,
            error: 'Dados de login inválidos.',
            code: 'AUTH_INVALID_INPUT'
        });
    }

    // 3. Busca o usuário (comparação case-insensitive segura)
    const user = USERS.find(u => u.username.toLowerCase() === usuario.toLowerCase().trim());

    if (!user) {
        logger.security('Tentativa de login com usuário inexistente', { ip, usuario });
        // Resposta genérica (não revela se o usuário existe — defesa de enumeração)
        return res.status(401).json({
            success: false,
            error: 'Usuário ou senha incorretos.',
            code: 'AUTH_INVALID_CREDENTIALS'
        });
    }

    // 4. Verificação da senha com bcrypt (timing-safe comparison)
    const senhaValida = await bcrypt.compare(senha, user.passwordHash);

    if (!senhaValida) {
        logger.security('Tentativa de login com senha incorreta', {
            ip,
            usuario: user.username
        });
        return res.status(401).json({
            success: false,
            error: 'Usuário ou senha incorretos.',
            code: 'AUTH_INVALID_CREDENTIALS'
        });
    }

    // 5. Gera o JWT com payload mínimo necessário
    const payload = {
        sub:    user.id,
        usuario: user.username,
        role:   user.role,
        nome:   user.nome,
        iat:    Math.floor(Date.now() / 1000)
    };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: EXPIRES_IN });

    logger.success('Login realizado com sucesso', {
        usuario: user.username,
        perfil: user.role,
        ip,
        expira: EXPIRES_IN
    });

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
 * Orientação: JWT é stateless. O logout é feito removendo o token no front-end.
 * Este endpoint existe para fins acadêmicos e geração de log de auditoria.
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

    return res.status(200).json({
        success: true,
        message: 'Logout registrado. Remova o token do armazenamento local.'
    });
});

module.exports = router;
