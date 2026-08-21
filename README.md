# ☕ Café Artisanal - Sistema de Cadastro com Segurança SSI & UX no Front-End

> **Disciplina**: Segurança em Sistemas da Informação (FICR)  
> **Tecnologias**: Node.js, Express, HTML5 Semântico, Vanilla CSS3 (Dark Coffee Theme), Vanilla JavaScript (ES6+).

---

## 📌 Visão Geral do Projeto

Este projeto é uma aplicação web completa desenvolvida em **Node.js** para gestão e cadastro de **Pessoas** (Clientes VIP, Funcionários e Baristas) e **Produtos** (Grãos, Bebidas Quentes, Bebidas Geladas, Lanches e Acessórios) para uma Cafeteria Gourmet.

O objetivo central do projeto é demonstrar, na prática e na teoria, a implementação dos **4 pilares fundamentais de Segurança e UX no Front-End**, acompanhado por um **Inspetor de Segurança em Tempo Real** na própria interface e por defesas em profundidade (*Defense in Depth*) no servidor Node.js.

---

## 🚀 Como Executar a Aplicação

### Pré-requisitos
- **Node.js** v18+ instalado.

### Passo a Passo

1. **Instalar as dependências** (Express, Cors):
   ```bash
   npm.cmd install
   ```

2. **Iniciar o Servidor Node.js**:
   ```bash
   node server.js
   ```
   *ou via script npm:*
   ```bash
   npm.cmd start
   ```
   ```bash
   npm run dev
   ```

3. **Acessar no Navegador**:
   Acesse a URL: `http://localhost:3000`

---

## 🛡️ Os 4 Pilares de Segurança & UX Implementados

### 1. Limite de Caracteres (`maxlength` e Validação JS)
* **Em Segurança**: Previne ataques de **Buffer Overflow** em nível de aplicação (quando dados massivos tentam exceder a memória alocada ou estourar a coluna do banco de dados) e combate ataques de **Payload Flooding / Negação de Serviço (DoS)**, onde o atacante tenta enviar megabytes de texto em um único campo para sobrecarregar o consumo de memória e banda do servidor.
* **Em UX**: Impede que o usuário cometa o erro de digitar dados excessivamente longos sem saber que serão cortados no banco. O formulário exibe um **contador numérico dinâmico** em tempo real (ex: `14 / 80`), mudando de cor quando se aproxima do limite.

### 2. Campos Obrigatórios (`required` e Validação Pré-submissão)
* **Em Segurança**: Assegura a **consistência do estado da aplicação** antes de qualquer transmissão para o servidor ou banco de dados. Evita a criação de objetos corrompidos ou incompletos no backend e exceções como `NullPointerException`.
* **Em UX**: Destaca visualmente com asterisco vermelho (`*`) os campos indispensáveis. Caso o usuário tente enviar o formulário incompleto, o Front-End bloqueia a submissão, destaca o contorno em vermelho e exibe uma mensagem de orientação clara.

### 3. Máscaras de Entrada (CPF, Telefone, Preço R$, SKU)
* **Em Segurança**: Atua como a primeira camada de **sanitização de input**. A máscara remove e bloqueia dinamicamente a digitação de caracteres especiais maliciosos (aspas simples `'`, tags `<script>` ou comandos SQL) em campos numéricos/formatados, reduzindo drasticamente superfícies de ataque como **SQL Injection** e **Cross-Site Scripting (XSS)**. O campo de CPF também executa o cálculo algorítmico do **Dígito Verificador (Módulo 11)**.
* **Em UX**: Aplica a pontuação e formatação padrão automaticamente (ex: `000.000.000-00`, `(81) 90000-0000`, `R$ 0,00`). O usuário não precisa se preocupar em digitar pontos, traços ou parênteses.

### 4. Tipagem de Inputs (`type="email"`, `type="number"`, `type="tel"`, `type="date"`)
* **Em Segurança**: Utiliza o motor de validação estrita nativo do navegador (*HTML5 Validation Engine*). O navegador invalida o formulário antes da submissão caso o formato exato não seja respeitado (ex: um e-mail sem `@` ou sem domínio), evitando tráfego inútil para o servidor.
* **Em UX**: Em dispositivos móveis (smartphones e tablets), ativa automaticamente o teclado otimizado para o tipo de dado:
  * `type="email"`: Teclado virtual com atalhos para `@` e `.com`.
  * `type="tel"` e `type="number"`: Teclado numérico direto e seletores integrados.

---

## 🎨 Recursos Diferenciais da Aplicação

1. **Inspetor de Segurança em Tempo Real (Sidebar)**:
   * Ao clicar ou digitar em qualquer campo dos formulários, um card interativo no lado direito da tela explica exatamente qual regra de Segurança e UX está protegendo aquele campo específico.
2. **Defesa em Profundidade no Server Node.js**:
   * O servidor Express (`server.js`) reaplica todas as validações de `maxlength`, campos obrigatórios e sanitização de dados no backend, além de definir cabeçalhos de segurança HTTP (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`) e limitar o tamanho máximo do payload JSON a 100kb.
3. **Escapamento contra XSS**:
   * Todos os dados exibidos nas tabelas passam pela função `escapeHtml()` antes da renderização no DOM.
4. **Design Moderno (Coffee Dark Theme)**:
   * Interface elaborada em Vanilla CSS3 com cores inspiradas em café artesanal torrado, efeito de vidro (*glassmorphism*), tipografia do Google Fonts (*Outfit* e *Playfair Display*) e micro-animações.

---

## 📂 Estrutura de Arquivos

```
Seguranca_em_Sistemas_da_Informacao_FICR/
├── package.json               # Configurações do Node.js e dependências
├── server.js                  # Servidor HTTP Node.js com Express e API RESTful
├── public/                    # Arquivos do Front-End
│   ├── index.html             # Estrutura HTML5 com campos tipados e semânticos
│   ├── css/
│   │   └── style.css          # Estilização CSS3 customizada e responsiva
│   └── js/
│       ├── masks.js           # Máscaras de entrada e validador de CPF (Modulo 11)
│       ├── validation.js      # Validações e repositório de explicações de segurança
│       └── app.js             # Controle de formulários, abas, inspetor e consumo da API
└── README.md                  # Documentação acadêmica do projeto
```
