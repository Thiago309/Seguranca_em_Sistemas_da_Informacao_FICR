/**
 * Rotas de Produtos — Café Artisanal
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
 * GET /api/produtos
 * Rota pública — retorna catálogo de produtos do banco de dados.
 */
router.get('/', async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    try {
        const produtos = await db.produtos.getAll();
        logger.info('Listagem de produtos consultada', {
            ip,
            banco: db.getDriverName(),
            registros: produtos.length
        });
        res.json({ success: true, count: produtos.length, data: produtos });
    } catch (err) {
        logger.error('Erro ao buscar produtos no banco de dados', {
            ip,
            banco: db.getDriverName(),
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao consultar dados.' });
    }
});

/**
 * POST /api/produtos
 * Rota PROTEGIDA por JWT — cadastra novo produto no banco de dados.
 */
router.post('/', verifyToken, async (req, res) => {
    const ip       = req.ip || req.connection.remoteAddress;
    const operador = req.user?.usuario || 'desconhecido';

    let { nome, categoria, preco, sku, estoque, descricao } = req.body;

    nome      = sanitize(nome);
    categoria = sanitize(categoria);
    sku       = sanitize(sku);
    descricao = sanitize(descricao || '');

    const precoNum   = parseFloat(preco);
    const estoqueNum = parseInt(estoque, 10);

    logger.info('Tentativa de cadastro de produto', {
        operador,
        ip,
        sku: sku || 'vazio'
    });

    // Validação de campos obrigatórios e tipos
    if (!nome || !categoria || isNaN(precoNum) || !sku || isNaN(estoqueNum)) {
        logger.warn('Cadastro de produto rejeitado: dados incompletos ou inválidos', {
            operador, ip,
            faltando: [!nome && 'nome', !categoria && 'categoria',
                       isNaN(precoNum) && 'preco', !sku && 'sku',
                       isNaN(estoqueNum) && 'estoque'].filter(Boolean).join(', ')
        });
        db.logsAuditoria.insert({
            nivel: 'WARN',
            mensagem: 'Cadastro de produto rejeitado: dados incompletos ou inválidos',
            detalhes: { operador, sku },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'Dados do produto inválidos ou incompletos.'
        });
    }

    // Validação de tamanhos (defesa extra contra buffer overflow em nível de aplicação)
    if (nome.length > 70 || sku.length > 20 || descricao.length > 250) {
        logger.security('Cadastro de produto bloqueado: limite de caracteres excedido', {
            operador, ip,
            nome_len: nome.length, sku_len: sku.length
        });
        db.logsAuditoria.insert({
            nivel: 'SECURITY',
            mensagem: 'Tentativa de Buffer Overflow: limite de caracteres excedido no produto',
            detalhes: { nome_len: nome.length, sku_len: sku.length },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'Limite de caracteres excedido.'
        });
    }

    // Validação de valores numéricos
    if (precoNum <= 0 || estoqueNum < 0) {
        logger.warn('Cadastro de produto rejeitado: valores numéricos inválidos', {
            operador, ip,
            preco: precoNum, estoque: estoqueNum
        });
        db.logsAuditoria.insert({
            nivel: 'WARN',
            mensagem: 'Cadastro de produto rejeitado: valores numéricos inválidos',
            detalhes: { preco: precoNum, estoque: estoqueNum },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'O preço deve ser maior que zero e o estoque não pode ser negativo.'
        });
    }

    const skuUpper = sku.toUpperCase();

    try {
        const novoProduto = await db.produtos.insert({
            nome,
            categoria,
            preco: precoNum,
            sku: skuUpper,
            estoque: estoqueNum,
            descricao
        });

        logger.success('Produto cadastrado com sucesso', {
            operador,
            ip,
            banco: db.getDriverName(),
            id: novoProduto.id,
            sku: skuUpper,
            nome,
            preco: `R$ ${precoNum.toFixed(2)}`
        });

        db.logsAuditoria.insert({
            nivel: 'SUCCESS',
            mensagem: `Produto cadastrado com sucesso: ${nome} (SKU: ${skuUpper})`,
            detalhes: { id: novoProduto.id, sku: skuUpper, nome, preco: precoNum, estoque: estoqueNum },
            ip,
            operador
        }).catch(() => {});

        res.status(201).json({
            success: true,
            message: 'Produto cadastrado com sucesso!',
            data: novoProduto
        });
    } catch (err) {
        // Trata violação de unicidade do SKU
        const isDuplicateSku =
            (err.code === '23505') ||
            (err.message && (
                err.message.includes('UNIQUE constraint failed') ||
                err.message.includes('duplicate key value') ||
                err.message.includes('produtos_sku_key')
            ));

        if (isDuplicateSku) {
            logger.warn('Cadastro de produto rejeitado: SKU já existente', {
                operador, ip, sku: skuUpper
            });
            db.logsAuditoria.insert({
                nivel: 'WARN',
                mensagem: `Tentativa de cadastro com SKU duplicado: ${skuUpper}`,
                detalhes: { sku: skuUpper },
                ip,
                operador
            }).catch(() => {});

            return res.status(409).json({
                success: false,
                error: `Já existe um produto cadastrado com o SKU "${skuUpper}". Utilize um código único.`
            });
        }

        logger.error('Erro ao inserir produto no banco de dados', {
            operador, ip,
            banco: db.getDriverName(),
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao salvar dados.' });
    }
});

/**
 * DELETE /api/produtos/:id
 * Rota PROTEGIDA por JWT — remove produto pelo ID.
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
            mensagem: 'Tentativa de DELETE com ID inválido em produtos',
            detalhes: { id_recebido: id },
            ip,
            operador
        }).catch(() => {});

        return res.status(400).json({
            success: false,
            error: 'ID inválido.'
        });
    }

    logger.info('Tentativa de remoção de produto', { operador, ip, id: idNum });

    try {
        const produto = await db.produtos.getById(idNum);
        if (!produto) {
            logger.warn('Tentativa de remover produto inexistente', { operador, ip, id: idNum });
            return res.status(404).json({ success: false, error: 'Produto não encontrado.' });
        }

        await db.produtos.delete(idNum);

        logger.success('Produto removido com sucesso', {
            operador,
            ip,
            banco: db.getDriverName(),
            id: idNum,
            sku: produto.sku,
            nome: produto.nome
        });

        db.logsAuditoria.insert({
            nivel: 'SUCCESS',
            mensagem: `Produto removido: ${produto.nome} (SKU: ${produto.sku})`,
            detalhes: { id: idNum, sku: produto.sku, nome: produto.nome },
            ip,
            operador
        }).catch(() => {});

        res.json({ success: true, message: 'Produto removido com sucesso.' });
    } catch (err) {
        logger.error('Erro ao deletar produto do banco de dados', {
            operador, ip, id: idNum,
            banco: db.getDriverName(),
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao remover dado.' });
    }
});

module.exports = router;
