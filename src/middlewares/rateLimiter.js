/**
 * Configurações de Rate Limiting — Café Artesanal
 *
 * Por que Rate Limiting:
 * Sem limitação de taxa, a API fica exposta a:
 *   - Ataque de Força Bruta: testar milhares de senhas por segundo na rota de login
 *   - DDoS de Aplicação: inundar o servidor com requisições para esgotar recursos
 *   - Data Scraping: extrair todos os registros do banco com requisições automatizadas
 *
 * O Rate Limiting é a primeira linha de defesa contra esses vetores (OWASP API4).
 * Cada limite tem um propósito específico e gera logs de segurança quando ativado.
 */

const rateLimit = require('express-rate-limit');
const logger    = require('../logger');

/**
 * Fábrica de handler customizado para quando o limite é excedido.
 * Gera log de segurança e resposta padronizada.
 */
function buildRateLimitHandler(limitName) {
    return (req, res) => {
        const ip = req.ip || req.connection.remoteAddress;
        logger.security(`Rate Limit atingido: ${limitName}`, {
            ip,
            rota: req.originalUrl,
            metodo: req.method
        });
        res.status(429).json({
            success: false,
            error: `Muitas requisições. Aguarde antes de tentar novamente.`,
            code: 'RATE_LIMIT_EXCEEDED',
            limitName
        });
    };
}

/**
 * 1. Limitador de Login (Anti Força Bruta)
 * 5 tentativas por 15 minutos por IP.
 * Protege contra ataques de dicionário e força bruta nas credenciais.
 * Não usa keyGenerator customizado — o express-rate-limit trata IPv4/IPv6 por padrão.
 */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    handler: buildRateLimitHandler('LOGIN_BRUTE_FORCE'),
    message: { success: false, error: 'Muitas tentativas de login. Aguarde 15 minutos.' }
});

/**
 * 2. Limitador Geral da API (Anti DDoS / Scraping)
 * 150 requisições por 15 minutos por IP.
 * Protege todas as rotas de leitura e navegação geral.
 */
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 150,
    standardHeaders: true,
    legacyHeaders: false,
    handler: buildRateLimitHandler('API_GENERAL'),
});

/**
 * 3. Limitador de Escrita (Anti Abuso / Spam de Cadastro)
 * 20 operações de escrita (POST/DELETE) por 10 minutos por IP.
 * Protege contra automação de cadastros e exclusões em massa.
 */
const writeLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutos
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: buildRateLimitHandler('WRITE_OPERATIONS'),
    skip: (req) => req.method === 'GET', // Aplica apenas em escrita
});

module.exports = { loginLimiter, apiLimiter, writeLimiter };
