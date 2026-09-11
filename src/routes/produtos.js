/**
 * Rotas de Produtos — Café Artisanal
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
 * GET /api/produtos
 * Rota pública — retorna lista de produtos do banco SQLite.
 * Usa Prepared Statement: SELECT * FROM produtos ORDER BY id DESC
 */
router.get('/', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    try {
        const produtos = queries.getAllProdutos.all();
        logger.info('Listagem de produtos consultada', {
            ip,
            registros: produtos.length
        });
        res.json({ success: true, count: produtos.length, data: produtos });
    } catch (err) {
        logger.error('Erro ao buscar produtos no banco de dados', {
            ip,
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao consultar dados.' });
    }
});

/**
 * POST /api/produtos
 * Rota PROTEGIDA por JWT — cadastra novo produto no banco SQLite.
 * Usa Prepared Statement: INSERT INTO produtos (?, ?, ?, ?, ?, ?)
 */
router.post('/', verifyToken, (req, res) => {
    const ip       = req.ip || req.connection.remoteAddress;
    const operador = req.user?.usuario || 'desconhecido';

    let { nome, categoria, preco, sku, estoque, descricao } = req.body;

    nome      = sanitize(nome);
    categoria = sanitize(categoria);
    sku       = sanitize(sku);
    descricao = sanitize(descricao || '');

    const precoNum    = parseFloat(preco);
    const estoqueNum  = parseInt(estoque, 10);

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
        return res.status(400).json({
            success: false,
            error: 'Dados do produto inválidos ou incompletos.'
        });
    }

    // Validação de tamanhos (defesa extra contra buffer overflow)
    if (nome.length > 70 || sku.length > 20 || descricao.length > 250) {
        logger.security('Cadastro de produto bloqueado: limite de caracteres excedido', {
            operador, ip,
            nome_len: nome.length, sku_len: sku.length
        });
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
        return res.status(400).json({
            success: false,
            error: 'O preço deve ser maior que zero e o estoque não pode ser negativo.'
        });
    }

    const skuUpper = sku.toUpperCase();

    try {
        // INSERT parametrizado — imune a SQL Injection
        const result = queries.insertProduto.run(
            nome, categoria, precoNum, skuUpper, estoqueNum, descricao
        );
        const novoProduto = queries.getProdutoById.get(result.lastInsertRowid);

        logger.success('Produto cadastrado com sucesso', {
            operador,
            ip,
            id: result.lastInsertRowid,
            sku: skuUpper,
            nome,
            preco: `R$ ${precoNum.toFixed(2)}`
        });

        res.status(201).json({
            success: true,
            message: 'Produto cadastrado com sucesso!',
            data: novoProduto
        });
    } catch (err) {
        // Trata violação de UNIQUE no SKU
        if (err.message && err.message.includes('UNIQUE constraint failed')) {
            logger.warn('Cadastro de produto rejeitado: SKU já existe', {
                operador, ip, sku: skuUpper
            });
            return res.status(409).json({
                success: false,
                error: `Já existe um produto com o SKU "${skuUpper}". Use um código único.`
            });
        }
        logger.error('Erro ao inserir produto no banco de dados', {
            operador, ip,
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao salvar dados.' });
    }
});

/**
 * DELETE /api/produtos/:id
 * Rota PROTEGIDA por JWT — remove produto pelo ID.
 * Usa Prepared Statement: DELETE FROM produtos WHERE id = ?
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

    logger.info('Tentativa de remoção de produto', { operador, ip, id: idNum });

    try {
        const produto = queries.getProdutoById.get(idNum);
        if (!produto) {
            logger.warn('Tentativa de remover produto inexistente', { operador, ip, id: idNum });
            return res.status(404).json({ success: false, error: 'Produto não encontrado.' });
        }

        queries.deleteProduto.run(idNum);

        logger.success('Produto removido com sucesso', {
            operador,
            ip,
            id: idNum,
            sku: produto.sku,
            nome: produto.nome
        });

        res.json({ success: true, message: 'Produto removido com sucesso.' });
    } catch (err) {
        logger.error('Erro ao deletar produto do banco de dados', {
            operador, ip, id: idNum,
            detalhe: err.message
        });
        res.status(500).json({ success: false, error: 'Erro interno ao remover dado.' });
    }
});

module.exports = router;
