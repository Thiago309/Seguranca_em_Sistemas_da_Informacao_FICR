/**
 * Rotas de Pessoas — Café Artesanal
 * Todas as operações usam chamadas parametrizadas (anti SQL Injection)
 * Todas as operações geram logs detalhados no terminal e trilha de auditoria
 * Suporta Supabase (PostgreSQL Cloud) e fallback SQLite
 */

const express = require('express');
const router  = express.Router();
const logger  = require('../logger');
const db      = require('../database');
const { verifyToken } = require('../middlewares/auth');

// Helper de sanitização server-side
function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.trim();
}

/**
 * GET /api/pessoas
 * Rota pública — retorna lista de pessoas do banco de dados.
 */
router.get('/', async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    try {
        const pessoas = await db.pessoas.getAll();
        logger.info('Listagem de pessoas consultada', {
            ip,
            banco: db.getDriverName(),
            registros: pessoas.length
        });
        res.json({ success: true, count: pessoas.length, data: pessoas });
    } catch (err) {
        logger.error('Erro ao buscar pessoas no banco de dados', {
            ip,
            banco: db.getDriverName(),
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao consultar dados.' });
    }
});

/**
 * POST /api/pessoas
 * Rota PROTEGIDA por JWT — cadastra nova pessoa no banco de dados.
 */
router.post('/', verifyToken, async (req, res) => {
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
        db.logsAuditoria.insert({
            nivel: 'WARN',
            mensagem: 'Cadastro de pessoa rejeitado: campos obrigatórios ausentes',
            detalhes: { operador, email },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'Todos os campos obrigatórios devem ser preenchidos.'
        });
    }

    // Validação de tamanhos (defesa extra contra buffer overflow em nível de aplicação)
    if (nome.length > 80 || email.length > 100 || cpf.length > 14 || telefone.length > 15) {
        logger.security('Cadastro de pessoa bloqueado: limite de caracteres excedido', {
            operador, ip,
            nome_len: nome.length, email_len: email.length
        });
        db.logsAuditoria.insert({
            nivel: 'SECURITY',
            mensagem: 'Tentativa de Buffer Overflow: limite de caracteres excedido no cadastro de pessoa',
            detalhes: { nome_len: nome.length, email_len: email.length },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'Limite de caracteres excedido em um ou mais campos.'
        });
    }

    // Validação de e-mail (regex no backend)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        logger.warn('Cadastro de pessoa rejeitado: e-mail inválido', { operador, ip, email });
        db.logsAuditoria.insert({
            nivel: 'WARN',
            mensagem: 'Cadastro de pessoa rejeitado: formato de e-mail inválido',
            detalhes: { email },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'Formato de e-mail inválido.'
        });
    }

    try {
        const novaPessoa = await db.pessoas.insert({ nome, cpf, email, telefone, tipo });

        logger.success('Pessoa cadastrada com sucesso', {
            operador,
            ip,
            banco: db.getDriverName(),
            id: novaPessoa.id,
            nome,
            tipo
        });

        db.logsAuditoria.insert({
            nivel: 'SUCCESS',
            mensagem: `Pessoa cadastrada com sucesso: ${nome} (${tipo})`,
            detalhes: { id: novaPessoa.id, nome, cpf, tipo },
            ip,
            operador
        }).catch(() => {});

        res.status(201).json({
            success: true,
            message: 'Pessoa cadastrada com sucesso!',
            data: novaPessoa
        });
    } catch (err) {
        logger.error('Erro ao inserir pessoa no banco de dados', {
            operador, ip,
            banco: db.getDriverName(),
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao salvar dados.' });
    }
});

/**
 * DELETE /api/pessoas/:id
 * Rota PROTEGIDA por JWT — remove pessoa pelo ID.
 */
router.delete('/:id', verifyToken, async (req, res) => {
    const ip       = req.ip || req.connection.remoteAddress;
    const operador = req.user?.usuario || 'desconhecido';
    const { id }   = req.params;

    // Valida que o ID é um número inteiro positivo
    const idNum = parseInt(id, 10);
    if (isNaN(idNum) || idNum <= 0) {
        logger.security('Tentativa de DELETE com ID inválido', {
            operador, ip, id_recebido: id
        });
        db.logsAuditoria.insert({
            nivel: 'SECURITY',
            mensagem: 'Tentativa de DELETE com ID inválido em pessoas',
            detalhes: { id_recebido: id },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'ID inválido.'
        });
    }

    logger.info('Tentativa de remoção de pessoa', { operador, ip, id: idNum });

    try {
        const pessoa = await db.pessoas.getById(idNum);
        if (!pessoa) {
            logger.warn('Tentativa de remover pessoa inexistente', { operador, ip, id: idNum });
            return res.status(404).json({ success: false, error: 'Pessoa não encontrada.' });
        }

        await db.pessoas.delete(idNum);

        logger.success('Pessoa removida com sucesso', {
            operador,
            ip,
            banco: db.getDriverName(),
            id: idNum,
            nome: pessoa.nome
        });

        db.logsAuditoria.insert({
            nivel: 'SUCCESS',
            mensagem: `Pessoa removida: ${pessoa.nome} (ID ${idNum})`,
            detalhes: { id: idNum, nome: pessoa.nome },
            ip,
            operador
        }).catch(() => {});

        res.json({ success: true, message: 'Registro removido com sucesso.' });
    } catch (err) {
        logger.error('Erro ao deletar pessoa do banco de dados', {
            operador, ip, id: idNum,
            banco: db.getDriverName(),
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao remover dado.' });
    }
});

module.exports = router;
