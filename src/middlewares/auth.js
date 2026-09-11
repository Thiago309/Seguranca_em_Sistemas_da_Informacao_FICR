/**
 * Middleware de Autenticação JWT — Café Artesanal
 *
 * Por que JWT (JSON Web Token):
 * JWT é o padrão RFC 7519 para autenticação stateless em APIs REST.
 * O token é assinado com uma chave secreta (HMAC SHA-256), garantindo
 * que seu conteúdo não pode ser forjado ou alterado sem invalidar a assinatura.
 * Isso garante que APENAS usuários autenticados possam escrever/deletar dados.
 *
 * Estrutura do JWT: Header.Payload.Signature
 *   - Header: algoritmo de assinatura (HS256)
 *   - Payload: dados do usuário (sub, role, iat, exp)
 *   - Signature: HMAC(base64(header) + "." + base64(payload), SECRET_KEY)
 *
 * O middleware verifica: existência, formato, assinatura e expiração.
 */

const jwt    = require('jsonwebtoken');
const logger = require('../logger');

const SECRET_KEY = process.env.JWT_SECRET || 'cafeteria_ssi_ficr_secret_2025_!@#$%';
const EXPIRES_IN = '2h';

/**
 * Middleware que protege rotas exigindo um JWT válido no header Authorization.
 * Uso: router.post('/rota-protegida', verifyToken, handler)
 */
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const ip = req.ip || req.connection.remoteAddress;

    // 1. Verifica se o header Authorization existe
    if (!authHeader) {
        logger.security('Tentativa de acesso sem token JWT', {
            rota: req.originalUrl,
            metodo: req.method,
            ip
        });
        return res.status(401).json({
            success: false,
            error: 'Acesso negado: Token de autenticação não fornecido.',
            code: 'AUTH_MISSING_TOKEN'
        });
    }

    // 2. Verifica o formato "Bearer <token>"
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        logger.security('Token JWT com formato inválido', {
            rota: req.originalUrl,
            ip,
            recebido: parts[0]
        });
        return res.status(401).json({
            success: false,
            error: 'Acesso negado: Formato do token inválido. Use: Authorization: Bearer <token>',
            code: 'AUTH_INVALID_FORMAT'
        });
    }

    const token = parts[1];

    // 3. Verifica a assinatura e a expiração do token
    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        // Anexa os dados do usuário à requisição para uso nos controllers
        req.user = decoded;

        logger.info('Acesso autenticado com JWT', {
            usuario: decoded.sub,
            perfil: decoded.role,
            rota: `${req.method} ${req.originalUrl}`,
            ip
        });

        next();
    } catch (err) {
        // Distingue token expirado de token inválido/adulterado
        if (err.name === 'TokenExpiredError') {
            logger.security('Tentativa com token JWT expirado', {
                rota: req.originalUrl,
                ip,
                expirou: err.expiredAt
            });
            return res.status(401).json({
                success: false,
                error: 'Token expirado. Faça login novamente.',
                code: 'AUTH_TOKEN_EXPIRED'
            });
        }

        logger.security('Tentativa com token JWT inválido/adulterado', {
            rota: req.originalUrl,
            ip,
            erro: err.message
        });
        return res.status(403).json({
            success: false,
            error: 'Token inválido ou adulterado.',
            code: 'AUTH_INVALID_TOKEN'
        });
    }
}

module.exports = { verifyToken, SECRET_KEY, EXPIRES_IN };
