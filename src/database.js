/**
 * Módulo de Banco de Dados — Supabase & Fallback Local (Café Artesanal)
 * Disciplina: Segurança em Sistemas da Informação (FICR)
 *
 * Princípios de Segurança:
 * 1. Prevenção de SQL Injection:
 *    A SDK do Supabase utiliza a API PostgREST por baixo dos panos, onde cada
 *    parâmetro é estritamente tipado e serializado via JSON / queries parametrizadas
 *    no PostgreSQL. Injeções de código SQL são estruturalmente impossíveis.
 * 2. Gestão Segura de Credenciais:
 *    Chaves e URL do Supabase são lidas do ambiente (.env), mantidas fora
 *    do controle de versão (.gitignore) conforme as recomendações OWASP.
 * 3. Trilha de Auditoria Forense:
 *    Tabela logs_auditoria para armazenar eventos de segurança e acessos.
 * 4. Controle de Acesso e Usuários (RBAC):
 *    Tabela usuarios armazena operadores com senhas em hash bcrypt.
 * 5. Resiliência Operacional (Fallback Gracioso):
 *    Se o desenvolvedor ainda não configurou as credenciais reais no .env,
 *    o sistema opera em modo local SQLite, garantindo continuidade sem falhas críticas.
 */

require('dotenv').config();
const path   = require('path');
const fs     = require('fs');
const logger = require('./logger');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

// Verifica se as credenciais do Supabase são reais (não placeholders)
const isConfiguredSupabase = Boolean(
    supabaseUrl &&
    supabaseKey &&
    !supabaseUrl.includes('seu-projeto') &&
    !supabaseKey.includes('sua-chave')
);

let supabaseClient = null;
let isSupabase = false;

if (isConfiguredSupabase) {
    try {
        const { createClient } = require('@supabase/supabase-js');
        supabaseClient = createClient(supabaseUrl, supabaseKey, {
            auth: {
                persistSession: false,
                autoRefreshToken: false
            }
        });
        isSupabase = true;
        logger.db('Conectado com sucesso ao Supabase Cloud (PostgreSQL)', {
            url: supabaseUrl.replace(/^(https?:\/\/[^.]+).*/, '$1.supabase.co')
        });
    } catch (err) {
        logger.error('Erro ao inicializar cliente Supabase:', { detalhe: err.message });
        isSupabase = false;
    }
} else {
    logger.warn('⚠️  Supabase não configurado ou credenciais de exemplo em .env');
    logger.info('💡 Para conectar ao Supabase:');
    logger.info('   1. Execute o script database/supabase_schema.sql no SQL Editor do Supabase');
    logger.info('   2. Adicione SUPABASE_URL e SUPABASE_KEY no arquivo .env');
    logger.info('🔄 Operando temporariamente no modo fallback local (SQLite)...');
}

// ============================================================
// INICIALIZAÇÃO DO BANCO LOCAL SQLITE (Para modo Fallback)
// ============================================================
const dbDir = path.join(__dirname, '..', 'database');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}
const dbPath = path.join(dbDir, 'cafeteria.db');

let localDb = null;
try {
    const Database = require('better-sqlite3');
    localDb = new Database(dbPath);
    localDb.pragma('journal_mode = WAL');
    localDb.pragma('foreign_keys = ON');

    localDb.exec(`
        CREATE TABLE IF NOT EXISTS pessoas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            nome        TEXT    NOT NULL CHECK(length(nome) <= 80),
            cpf         TEXT    NOT NULL CHECK(length(cpf) <= 14),
            email       TEXT    NOT NULL CHECK(length(email) <= 100),
            telefone    TEXT    NOT NULL CHECK(length(telefone) <= 15),
            tipo        TEXT    NOT NULL,
            dataCadastro TEXT   NOT NULL DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS produtos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            nome        TEXT    NOT NULL CHECK(length(nome) <= 70),
            categoria   TEXT    NOT NULL,
            preco       REAL    NOT NULL CHECK(preco > 0),
            sku         TEXT    NOT NULL UNIQUE CHECK(length(sku) <= 20),
            estoque     INTEGER NOT NULL CHECK(estoque >= 0),
            descricao   TEXT             CHECK(length(descricao) <= 250),
            dataCadastro TEXT   NOT NULL DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS usuarios (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'operador',
            nome          TEXT    NOT NULL,
            data_cadastro TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
        );

        CREATE TABLE IF NOT EXISTS logs_auditoria (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            nivel       TEXT    NOT NULL,
            mensagem    TEXT    NOT NULL,
            detalhes    TEXT,
            ip          TEXT,
            operador    TEXT,
            data_hora   TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
    `);

    // Seeds locais de pessoas
    const countP = localDb.prepare('SELECT COUNT(*) as total FROM pessoas').get();
    if (countP.total === 0) {
        const insP = localDb.prepare('INSERT INTO pessoas (nome, cpf, email, telefone, tipo) VALUES (?, ?, ?, ?, ?)');
        insP.run('Ana Beatriz Souza', '123.456.789-00', 'ana.souza@email.com', '(81) 98765-4321', 'Cliente VIP');
        insP.run('Carlos Eduardo Silva', '987.654.321-11', 'carlos.barista@cafearoma.com.br', '(81) 99123-8899', 'Barista (Funcionário)');
    }

    // Seeds locais de produtos
    const countPr = localDb.prepare('SELECT COUNT(*) as total FROM produtos').get();
    if (countPr.total === 0) {
        const insPr = localDb.prepare('INSERT INTO produtos (nome, categoria, preco, sku, estoque, descricao) VALUES (?, ?, ?, ?, ?, ?)');
        insPr.run('Espresso Gourmet Arábica 250g', 'Grãos & Pós', 34.90, 'CAF-ESP-250', 45, 'Grãos selecionados 100% Arábica com notas de chocolate amargo e avelã.');
        insPr.run('Cappuccino Italiano Clássico', 'Bebidas Quentes', 16.50, 'BEB-CAP-ITA', 100, 'Espresso duplo, leite vaporizado e espuma cremosa com toque de canela.');
        insPr.run('Croissant de Amêndoas', 'Lanches & Sobremesas', 18.00, 'LAN-CRO-AME', 20, 'Massa folhada artesanal recheada e coberta com lâminas de amêndoas tostadas.');
    }

    // Seeds locais de usuários
    const countU = localDb.prepare('SELECT COUNT(*) as total FROM usuarios').get();
    if (countU.total === 0) {
        const insU = localDb.prepare('INSERT INTO usuarios (username, password_hash, role, nome) VALUES (?, ?, ?, ?)');
        insU.run('admin', '$2b$10$aQXpxtlzIQ0eQRB.JEZJOe0JcOF/VZXeieG6yyvrtuIvuni7aajly', 'administrador', 'Administrador do Sistema');
        insU.run('gerente', '$2b$10$cV1CO5x6MmWE7EXJKdyc7uvdvEqnRgkcdk7NCvDVJTmUlrm0LATuq', 'gerente', 'Gerente da Cafeteria');
    }

    if (!isSupabase) {
        logger.db('Conexão de fallback com SQLite local ativa', { arquivo: 'database/cafeteria.db' });
    }
} catch (err) {
    logger.error('Falha ao inicializar SQLite local:', { detalhe: err.message });
}

// ============================================================
// INTERFACE UNIFICADA DE BANCO DE DADOS (Assíncrona)
// ============================================================
const db = {
    isSupabase: () => isSupabase,
    getDriverName: () => (isSupabase ? 'Supabase (PostgreSQL Cloud)' : 'SQLite (Fallback Local)'),

    // --- PESSOAS ---
    pessoas: {
        async getAll() {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('pessoas')
                    .select('*')
                    .order('id', { ascending: false });
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return data || [];
            } else {
                return localDb.prepare('SELECT * FROM pessoas ORDER BY id DESC').all();
            }
        },

        async getById(id) {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('pessoas')
                    .select('*')
                    .eq('id', id)
                    .maybeSingle();
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return data;
            } else {
                return localDb.prepare('SELECT * FROM pessoas WHERE id = ?').get(id);
            }
        },

        async insert({ nome, cpf, email, telefone, tipo }) {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('pessoas')
                    .insert([{ nome, cpf, email, telefone, tipo }])
                    .select()
                    .single();
                if (error) throw error;
                return data;
            } else {
                const stmt = localDb.prepare('INSERT INTO pessoas (nome, cpf, email, telefone, tipo) VALUES (?, ?, ?, ?, ?)');
                const result = stmt.run(nome, cpf, email, telefone, tipo);
                return localDb.prepare('SELECT * FROM pessoas WHERE id = ?').get(result.lastInsertRowid);
            }
        },

        async delete(id) {
            if (isSupabase) {
                const { error } = await supabaseClient
                    .from('pessoas')
                    .delete()
                    .eq('id', id);
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return true;
            } else {
                localDb.prepare('DELETE FROM pessoas WHERE id = ?').run(id);
                return true;
            }
        }
    },

    // --- PRODUTOS ---
    produtos: {
        async getAll() {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('produtos')
                    .select('*')
                    .order('id', { ascending: false });
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return data || [];
            } else {
                return localDb.prepare('SELECT * FROM produtos ORDER BY id DESC').all();
            }
        },

        async getById(id) {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('produtos')
                    .select('*')
                    .eq('id', id)
                    .maybeSingle();
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return data;
            } else {
                return localDb.prepare('SELECT * FROM produtos WHERE id = ?').get(id);
            }
        },

        async insert({ nome, categoria, preco, sku, estoque, descricao }) {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('produtos')
                    .insert([{ nome, categoria, preco, sku, estoque, descricao }])
                    .select()
                    .single();
                if (error) throw error;
                return data;
            } else {
                const stmt = localDb.prepare(
                    'INSERT INTO produtos (nome, categoria, preco, sku, estoque, descricao) VALUES (?, ?, ?, ?, ?, ?)'
                );
                const result = stmt.run(nome, categoria, preco, sku, estoque, descricao);
                return localDb.prepare('SELECT * FROM produtos WHERE id = ?').get(result.lastInsertRowid);
            }
        },

        async delete(id) {
            if (isSupabase) {
                const { error } = await supabaseClient
                    .from('produtos')
                    .delete()
                    .eq('id', id);
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return true;
            } else {
                localDb.prepare('DELETE FROM produtos WHERE id = ?').run(id);
                return true;
            }
        }
    },

    // --- USUÁRIOS (Autenticação / RBAC) ---
    usuarios: {
        async getByUsername(username) {
            if (!username) return null;
            const cleanUser = String(username).trim();

            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('usuarios')
                    .select('*')
                    .ilike('username', cleanUser)
                    .maybeSingle();
                if (error) {
                    logger.warn('Aviso ao consultar usuario no Supabase:', { detalhe: error.message });
                    return null;
                }
                return data;
            } else {
                return localDb.prepare('SELECT * FROM usuarios WHERE LOWER(username) = LOWER(?)').get(cleanUser);
            }
        },

        async getAll() {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('usuarios')
                    .select('id, username, role, nome, data_cadastro')
                    .order('id');
                if (error) throw new Error(`Supabase error: ${error.message}`);
                return data || [];
            } else {
                return localDb.prepare('SELECT id, username, role, nome, data_cadastro FROM usuarios ORDER BY id').all();
            }
        }
    },

    // --- LOGS DE AUDITORIA (Trilha Forense de Segurança) ---
    logsAuditoria: {
        async insert({ nivel, mensagem, detalhes = null, ip = null, operador = null }) {
            try {
                if (isSupabase) {
                    await supabaseClient.from('logs_auditoria').insert([{
                        nivel,
                        mensagem,
                        detalhes: detalhes || null,
                        ip: ip || null,
                        operador: operador || null
                    }]);
                } else if (localDb) {
                    const stmt = localDb.prepare(
                        'INSERT INTO logs_auditoria (nivel, mensagem, detalhes, ip, operador) VALUES (?, ?, ?, ?, ?)'
                    );
                    stmt.run(
                        nivel,
                        mensagem,
                        detalhes ? (typeof detalhes === 'object' ? JSON.stringify(detalhes) : String(detalhes)) : null,
                        ip || null,
                        operador || null
                    );
                }
            } catch (err) {
                // Silencioso para não interromper o fluxo principal
            }
        },

        async getRecent(limit = 50) {
            if (isSupabase) {
                const { data, error } = await supabaseClient
                    .from('logs_auditoria')
                    .select('*')
                    .order('id', { ascending: false })
                    .limit(limit);
                if (error) {
                    logger.warn('Aviso ao consultar logs_auditoria no Supabase:', { detalhe: error.message });
                    return [];
                }
                return data || [];
            } else {
                return localDb.prepare('SELECT * FROM logs_auditoria ORDER BY id DESC LIMIT ?').all(limit);
            }
        }
    },

    // --- ESTATÍSTICAS DO DASHBOARD ---
    stats: {
        async getStats() {
            if (isSupabase) {
                const [pRes, prRes, stRes] = await Promise.all([
                    supabaseClient.from('pessoas').select('*', { count: 'exact', head: true }),
                    supabaseClient.from('produtos').select('*', { count: 'exact', head: true }),
                    supabaseClient.from('produtos').select('estoque')
                ]);

                if (pRes.error) throw new Error(`Supabase stats pessoas: ${pRes.error.message}`);
                if (prRes.error) throw new Error(`Supabase stats produtos: ${prRes.error.message}`);

                const totalEstoque = (stRes.data || []).reduce(
                    (sum, item) => sum + (Number(item.estoque) || 0),
                    0
                );

                return {
                    totalPessoas: pRes.count || 0,
                    totalProdutos: prRes.count || 0,
                    totalEstoque
                };
            } else {
                const totalPessoas  = localDb.prepare('SELECT COUNT(*) as total FROM pessoas').get().total;
                const totalProdutos = localDb.prepare('SELECT COUNT(*) as total FROM produtos').get().total;
                const totalEstoque  = localDb.prepare('SELECT COALESCE(SUM(estoque), 0) as total FROM produtos').get().total;
                return { totalPessoas, totalProdutos, totalEstoque };
            }
        }
    }
};

module.exports = db;
