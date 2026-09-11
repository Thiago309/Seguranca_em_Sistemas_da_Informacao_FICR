/**
 * Logger Customizado — Café Artesanal Security Back-End
 * Exibe logs coloridos no terminal com níveis: INFO, WARN, ERROR, SECURITY
 *
 * Por que é importante:
 * Auditoria é um pilar de segurança (ISO 27001, OWASP ASVS). Logs permitem
 * rastrear tentativas de ataque, falhas de autenticação e comportamentos
 * suspeitos. Sem logs, a aplicação é cega a incidentes de segurança.
 */

const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[2m';

const COLORS = {
    INFO:     '\x1b[36m',  // Ciano
    WARN:     '\x1b[33m',  // Amarelo
    ERROR:    '\x1b[31m',  // Vermelho
    SECURITY: '\x1b[35m',  // Magenta
    SUCCESS:  '\x1b[32m',  // Verde
    DB:       '\x1b[34m',  // Azul
};

const ICONS = {
    INFO:     '📋',
    WARN:     '⚠️ ',
    ERROR:    '❌',
    SECURITY: '🛡️ ',
    SUCCESS:  '✅',
    DB:       '🗃️ ',
};

/**
 * Formata e exibe um log no terminal
 * @param {string} level - Nível do log
 * @param {string} message - Mensagem principal
 * @param {Object} [meta] - Metadados extras (IP, rota, usuário, etc.)
 */
function log(level, message, meta = null) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 23);
    const color = COLORS[level] || RESET;
    const icon = ICONS[level] || '';

    let output = `${DIM}[${timestamp}]${RESET} ${color}${BOLD}[${level.padEnd(8)}]${RESET} ${icon} ${message}`;

    if (meta && Object.keys(meta).length > 0) {
        const metaStr = Object.entries(meta)
            .map(([k, v]) => `${DIM}${k}=${RESET}${color}${v}${RESET}`)
            .join(' | ');
        output += `  ${DIM}→${RESET} ${metaStr}`;
    }

    console.log(output);
}

const logger = {
    info:     (msg, meta) => log('INFO', msg, meta),
    warn:     (msg, meta) => log('WARN', msg, meta),
    error:    (msg, meta) => log('ERROR', msg, meta),
    security: (msg, meta) => log('SECURITY', msg, meta),
    success:  (msg, meta) => log('SUCCESS', msg, meta),
    db:       (msg, meta) => log('DB', msg, meta),

    /**
     * Formato especial para o header de inicialização do servidor
     */
    banner() {
        const line = '═'.repeat(58);
        console.log(`\n${COLORS.SUCCESS}${BOLD}╔${line}╗${RESET}`);
        console.log(`${COLORS.SUCCESS}${BOLD}║${RESET}  ☕  ${BOLD}CAFÉ ARTESANAL — BACK-END SEGURO${RESET}${' '.repeat(21)}${COLORS.SUCCESS}${BOLD}║${RESET}`);
        console.log(`${COLORS.SUCCESS}${BOLD}║${RESET}  🛡️   Segurança em Sistemas da Informação — FICR${' '.repeat(10)}${COLORS.SUCCESS}${BOLD}║${RESET}`);
        console.log(`${COLORS.SUCCESS}${BOLD}╚${line}╝${RESET}`);
    },

    /**
     * Log de requisição HTTP - usado pelo middleware morgan
     */
    httpFormat: ':method :url :status :response-time ms — :remote-addr'
};

module.exports = logger;
