const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware de Segurança Basica (Defense in Depth)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

app.use(cors());
app.use(express.json({ limit: '100kb' })); // Restrição de tamanho de payload no backend (prevenção DoS)
app.use(express.static(path.join(__dirname, 'public')));

// Base de dados em memória com dados iniciais de exemplo (Cafeteria Gourmet)
let pessoas = [
    {
        id: "1",
        nome: "Ana Beatriz Souza",
        cpf: "123.456.789-00",
        email: "ana.souza@email.com",
        telefone: "(81) 98765-4321",
        tipo: "Cliente VIP",
        dataCadastro: new Date().toISOString()
    },
    {
        id: "2",
        nome: "Carlos Eduardo Silva",
        cpf: "987.654.321-11",
        email: "carlos.barista@cafearoma.com.br",
        telefone: "(81) 99123-8899",
        tipo: "Barista (Funcionário)",
        dataCadastro: new Date().toISOString()
    }
];

let produtos = [
    {
        id: "101",
        nome: "Espresso Gourmet Arábica 250g",
        categoria: "Grãos & Pós",
        preco: 34.90,
        sku: "CAF-ESP-250",
        estoque: 45,
        descricao: "Grãos selecionados 100% Arábica com notas de chocolate amargo e avelã.",
        dataCadastro: new Date().toISOString()
    },
    {
        id: "102",
        nome: "Cappuccino Italiano Clássico",
        categoria: "Bebidas Quentes",
        preco: 16.50,
        sku: "BEB-CAP-ITA",
        estoque: 100,
        descricao: "Espresso duplo, leite vaporizado e espuma cremosa com toque de canela.",
        dataCadastro: new Date().toISOString()
    },
    {
        id: "103",
        nome: "Croissant de Amêndoas",
        categoria: "Lanches & Sobremesas",
        preco: 18.00,
        sku: "LAN-CRO-AME",
        estoque: 20,
        descricao: "Massa folhada artesanal recheada e coberta com lâminas de amêndoas tostadas.",
        dataCadastro: new Date().toISOString()
    }
];

// Helper para sanitização e validação server-side
function sanitizeString(str) {
    if (typeof str !== 'string') return '';
    return str.trim();
}

// ----------------------------------------------------
// ROTAS DE API: PESSOAS
// ----------------------------------------------------
app.get('/api/pessoas', (req, res) => {
    res.json({ success: true, count: pessoas.length, data: pessoas });
});

app.post('/api/pessoas', (req, res) => {
    let { nome, cpf, email, telefone, tipo } = req.body;

    nome = sanitizeString(nome);
    cpf = sanitizeString(cpf);
    email = sanitizeString(email);
    telefone = sanitizeString(telefone);
    tipo = sanitizeString(tipo);

    // Validações de Segurança Server-Side (Campos Obrigatórios & Limites de Caracteres)
    if (!nome || !cpf || !email || !telefone || !tipo) {
        return res.status(400).json({
            success: false,
            error: "Validação Server-side: Todos os campos obrigatórios devem ser preenchidos."
        });
    }

    if (nome.length > 80 || email.length > 100 || cpf.length > 14 || telefone.length > 15) {
        return res.status(400).json({
            success: false,
            error: "Validação Server-side: Limite de caracteres excedido em um ou mais campos."
        });
    }

    // Regex básico de email no backend
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            success: false,
            error: "Validação Server-side: Formato de e-mail inválido."
        });
    }

    const novaPessoa = {
        id: Date.now().toString(),
        nome,
        cpf,
        email,
        telefone,
        tipo,
        dataCadastro: new Date().toISOString()
    };

    pessoas.unshift(novaPessoa);
    res.status(201).json({ success: true, message: "Pessoa cadastrada com sucesso!", data: novaPessoa });
});

app.delete('/api/pessoas/:id', (req, res) => {
    const { id } = req.params;
    const initialLength = pessoas.length;
    pessoas = pessoas.filter(p => p.id !== id);
    
    if (pessoas.length === initialLength) {
        return res.status(404).json({ success: false, error: "Pessoa não encontrada." });
    }
    
    res.json({ success: true, message: "Registro removido com sucesso." });
});

// ----------------------------------------------------
// ROTAS DE API: PRODUTOS
// ----------------------------------------------------
app.get('/api/produtos', (req, res) => {
    res.json({ success: true, count: produtos.length, data: produtos });
});

app.post('/api/produtos', (req, res) => {
    let { nome, categoria, preco, sku, estoque, descricao } = req.body;

    nome = sanitizeString(nome);
    categoria = sanitizeString(categoria);
    sku = sanitizeString(sku);
    descricao = sanitizeString(descricao);
    const precoNum = parseFloat(preco);
    const estoqueNum = parseInt(estoque, 10);

    // Validações de Segurança & Estado Consistente
    if (!nome || !categoria || isNaN(precoNum) || !sku || isNaN(estoqueNum)) {
        return res.status(400).json({
            success: false,
            error: "Validação Server-side: Dados do produto inválidos ou incompletos."
        });
    }

    if (nome.length > 70 || sku.length > 20 || descricao.length > 250) {
        return res.status(400).json({
            success: false,
            error: "Validação Server-side: Limite de caracteres excedido."
        });
    }

    if (precoNum <= 0 || estoqueNum < 0) {
        return res.status(400).json({
            success: false,
            error: "Validação Server-side: O preço deve ser maior que zero e o estoque não pode ser negativo."
        });
    }

    const novoProduto = {
        id: (100 + produtos.length + 1).toString(),
        nome,
        categoria,
        preco: precoNum,
        sku: sku.toUpperCase(),
        estoque: estoqueNum,
        descricao,
        dataCadastro: new Date().toISOString()
    };

    produtos.unshift(novoProduto);
    res.status(201).json({ success: true, message: "Produto cadastrado com sucesso!", data: novoProduto });
});

app.delete('/api/produtos/:id', (req, res) => {
    const { id } = req.params;
    const initialLength = produtos.length;
    produtos = produtos.filter(p => p.id !== id);

    if (produtos.length === initialLength) {
        return res.status(404).json({ success: false, error: "Produto não encontrado." });
    }

    res.json({ success: true, message: "Produto removido com sucesso." });
});

// Stats para Dashboard
app.get('/api/stats', (req, res) => {
    res.json({
        totalPessoas: pessoas.length,
        totalProdutos: produtos.length,
        totalEstoque: produtos.reduce((acc, p) => acc + p.estoque, 0)
    });
});

app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`☕ Servidor Cafeteria em execução na porta http://localhost:${PORT}`);
    console.log(`🛡️ Segurança & UX Front-End ativados`);
    console.log(`====================================================`);
});
