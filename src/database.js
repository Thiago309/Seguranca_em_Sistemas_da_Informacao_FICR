/**
 * Módulo de Banco de Dados SQLite — Café Artisanal
 *
 * Por que SQLite com Prepared Statements:
 * SQL Injection ocorre quando dados do usuário são concatenados diretamente
 * em queries SQL. Prepared Statements (queries parametrizadas) separam o
 * código SQL dos dados, tornando injeções estruturalmente impossíveis.
 * É o único método recomendado pelo OWASP para interação com bancos de dados.
 *
 * Exemplo de VULNERÁVEL (NUNCA fazer):
 *   db.query("SELECT * FROM pessoas WHERE id = '" + req.params.id + "'")
 *   → Atacante pode enviar: id = "'; DROP TABLE pessoas; --"
 *
 * Exemplo de SEGURO (como fazemos aqui):
 *   db.prepare("SELECT * FROM pessoas WHERE id = ?").get(id)
 *   → O banco trata o parâmetro como dado, jamais como código SQL
 */

const path    = require('path');
const fs      = require('fs');
const logger  = require('./logger');

// Garante que o diretório do banco existe
const dbDir = path.join(__dirname, '..', 'database');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'cafeteria.db');

let db;
try {
    const Database = require('better-sqlite3');
    db = new Database(dbPath);
    // WAL mode melhora a performance e concorrência do SQLite
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    logger.db('Conexão com banco de dados estabelecida', { arquivo: 'database/cafeteria.db' });
} catch (err) {
    logger.error('Falha ao conectar com o banco de dados SQLite', { detalhe: err.message });
    process.exit(1);
}

// ============================================================
// CRIAÇÃO DAS TABELAS (DDL com Prepared Statements via exec)
// ============================================================
db.exec(`
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
`);

logger.db('Estrutura de tabelas verificada / criada com sucesso');

// ============================================================
// SEED: Dados iniciais (apenas se as tabelas estiverem vazias)
// ============================================================
const countPessoas  = db.prepare('SELECT COUNT(*) as total FROM pessoas').get();
const countProdutos = db.prepare('SELECT COUNT(*) as total FROM produtos').get();

if (countPessoas.total === 0) {
    const insertPessoa = db.prepare(`
        INSERT INTO pessoas (nome, cpf, email, telefone, tipo)
        VALUES (?, ?, ?, ?, ?)
    `);
    // Todas as inserções são parametrizadas — imunes a SQL Injection
    insertPessoa.run('Ana Beatriz Souza',   '123.456.789-00', 'ana.souza@email.com',           '(81) 98765-4321', 'Cliente VIP');
    insertPessoa.run('Carlos Eduardo Silva', '987.654.321-11', 'carlos.barista@cafearoma.com.br', '(81) 99123-8899', 'Barista (Funcionário)');
    logger.db('Seed de pessoas inserido', { registros: 2 });
}

if (countProdutos.total === 0) {
    const insertProduto = db.prepare(`
        INSERT INTO produtos (nome, categoria, preco, sku, estoque, descricao)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    insertProduto.run('Espresso Gourmet Arábica 250g', 'Grãos & Pós',        34.90, 'CAF-ESP-250', 45,  'Grãos selecionados 100% Arábica com notas de chocolate amargo e avelã.');
    insertProduto.run('Cappuccino Italiano Clássico',  'Bebidas Quentes',     16.50, 'BEB-CAP-ITA', 100, 'Espresso duplo, leite vaporizado e espuma cremosa com toque de canela.');
    insertProduto.run('Croissant de Amêndoas',         'Lanches & Sobremesas', 18.00, 'LAN-CRO-AME', 20,  'Massa folhada artesanal recheada e coberta com lâminas de amêndoas tostadas.');
    logger.db('Seed de produtos inserido', { registros: 3 });
}

// ============================================================
// QUERIES PREPARADAS (Prepared Statements reutilizáveis)
// Cada ? representa um parâmetro seguro — jamais código executável
// ============================================================
const queries = {
    // Pessoas
    getAllPessoas:    db.prepare('SELECT * FROM pessoas ORDER BY id DESC'),
    getPessoaById:   db.prepare('SELECT * FROM pessoas WHERE id = ?'),
    insertPessoa:    db.prepare('INSERT INTO pessoas (nome, cpf, email, telefone, tipo) VALUES (?, ?, ?, ?, ?)'),
    deletePessoa:    db.prepare('DELETE FROM pessoas WHERE id = ?'),

    // Produtos
    getAllProdutos:   db.prepare('SELECT * FROM produtos ORDER BY id DESC'),
    getProdutoById:  db.prepare('SELECT * FROM produtos WHERE id = ?'),
    insertProduto:   db.prepare('INSERT INTO produtos (nome, categoria, preco, sku, estoque, descricao) VALUES (?, ?, ?, ?, ?, ?)'),
    deleteProduto:   db.prepare('DELETE FROM produtos WHERE id = ?'),

    // Stats
    countPessoas:    db.prepare('SELECT COUNT(*) as total FROM pessoas'),
    countProdutos:   db.prepare('SELECT COUNT(*) as total FROM produtos'),
    sumEstoque:      db.prepare('SELECT COALESCE(SUM(estoque), 0) as total FROM produtos'),
};

module.exports = { db, queries };
