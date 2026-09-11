/**
 * Rotas de Pessoas — Café Artisanal
 * Todas as queries usam Prepared Statements (anti SQL Injection)
 * Todas as operações geram logs detalhados no terminal
 */

const express = require('express');
const router  = express.Router();
const logger  = require('../logger');
const { queries } = require('../database');
const { verifyToken } = require('../middlewares/auth');

// Helper de sanitização server-side
function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.trim();
}

/**
 * GET /api/pessoas
 * Rota pública — retorna lista de pessoas do banco SQLite.
 * Usa Prepared Statement: SELECT * FROM pessoas ORDER BY id DESC
 */
router.get('/', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    try {
        const pessoas = queries.getAllPessoas.all();
        logger.info('Listagem de pessoas consultada', {
            ip,
            registros: pessoas.length
        });
        res.json({ success: true, count: pessoas.length, data: pessoas });
    } catch (err) {
        logger.error('Erro ao buscar pessoas no banco de dados', {
            ip,
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao consultar dados.' });
    }
});

/**
 * POST /api/pessoas
 * Rota PROTEGIDA por JWT — cadastra nova pessoa no banco SQLite.
 * Usa Prepared Statement: INSERT INTO pessoas (?, ?, ?, ?, ?)
 *
 * A defesa contra SQL Injection está na parametrização:
 * mesmo que o usuário envie: nome = "'; DROP TABLE pessoas; --"
 * o banco tratará esse texto como dado literal, não como código SQL.
 */
router.post('/', verifyToken, (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    const operador = req.user?.usuario || 'desconhecido';

    let { nome, cpf, email, telefone, tipo } = req.body;

    nome     = sanitize(nome);
    cpf      = sanitize(cpf);
    email    = sanitize(email);
    telefone = sanitize(telefone);
    tipo     = sanitize(tipo);

    logger.info('Tentativa de cadastro de pessoa', {
        operador,
        ip,
        email: email || 'vazio'
    });

    // Validação de campos obrigatórios
    if (!nome || !cpf || !email || !telefone || !tipo) {
        logger.warn('Cadastro de pessoa rejeitado: campos obrigatórios ausentes', {
            operador, ip,
            faltando: [!nome && 'nome', !cpf && 'cpf', !email && 'email',
                       !telefone && 'telefone', !tipo && 'tipo'].filter(Boolean).join(', ')
        });
        return res.status(400).json({
            success: false,
            error: 'Todos os campos obrigatórios devem ser preenchidos.'
        });
    }

    // Validação de tamanhos (defesa extra contra buffer overflow)
    if (nome.length > 80 || email.length > 100 || cpf.length > 14 || telefone.length > 15) {
        logger.security('Cadastro de pessoa bloqueado: limite de caracteres excedido', {
            operador, ip,
            nome_len: nome.length, email_len: email.length
        });
        return res.status(400).json({
            success: false,
            error: 'Limite de caracteres excedido em um ou mais campos.'
        });
    }

    // Validação de e-mail (regex no backend)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        logger.warn('Cadastro de pessoa rejeitado: e-mail inválido', { operador, ip, email });
        return res.status(400).json({
            success: false,
            error: 'Formato de e-mail inválido.'
        });
    }

    try {
        // INSERT parametrizado — os valores são tratados como dados puros pelo SQLite
        const result = queries.insertPessoa.run(nome, cpf, email, telefone, tipo);
        const novaPessoa = queries.getPessoaById.get(result.lastInsertRowid);

        logger.success('Pessoa cadastrada com sucesso', {
            operador,
            ip,
            id: result.lastInsertRowid,
            nome,
            tipo
        });

        res.status(201).json({
            success: true,
            message: 'Pessoa cadastrada com sucesso!',
            data: novaPessoa
        });
    } catch (err) {
        logger.error('Erro ao inserir pessoa no banco de dados', {
            operador, ip,
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao salvar dados.' });
    }
});

/**
 * DELETE /api/pessoas/:id
 * Rota PROTEGIDA por JWT — remove pessoa pelo ID.
 * Usa Prepared Statement: DELETE FROM pessoas WHERE id = ?
 *
 * O parâmetro :id é passado com ? no Prepared Statement,
 * não concatenado na query, eliminando SQL Injection.
 */
router.delete('/:id', verifyToken, (req, res) => {
    const ip       = req.ip || req.connection.remoteAddress;
    const operador = req.user?.usuario || 'desconhecido';
    const { id }   = req.params;

    // Valida que o ID é um número inteiro positivo
    const idNum = parseInt(id, 10);
    if (isNaN(idNum) || idNum <= 0) {
        logger.security('Tentativa de DELETE com ID inválido', {
            operador, ip, id_recebido: id
        });
        return res.status(400).json({
            success: false,
            error: 'ID inválido.'
        });
    }

    logger.info('Tentativa de remoção de pessoa', { operador, ip, id: idNum });

    try {
        const pessoa = queries.getPessoaById.get(idNum);
        if (!pessoa) {
            logger.warn('Tentativa de remover pessoa inexistente', { operador, ip, id: idNum });
            return res.status(404).json({ success: false, error: 'Pessoa não encontrada.' });
        }

        queries.deletePessoa.run(idNum);

        logger.success('Pessoa removida com sucesso', {
            operador,
            ip,
            id: idNum,
            nome: pessoa.nome
        });

        res.json({ success: true, message: 'Registro removido com sucesso.' });
    } catch (err) {
        logger.error('Erro ao deletar pessoa do banco de dados', {
            operador, ip, id: idNum,
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao remover dado.' });
    }
});

module.exports = router;
