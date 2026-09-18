/**
 * Controlador Principal da Aplicação Front-End (Café Artesanal)
 * Atualizado com suporte a Autenticação JWT
 */

// ============================================================
// MÓDULO DE AUTENTICAÇÃO JWT (Front-End)
// O token é armazenado em sessionStorage (não localStorage),
// pois sessionStorage é limpo ao fechar a aba (mais seguro).
// ============================================================
const Auth = {
    TOKEN_KEY: 'cafe_jwt_token',
    USER_KEY:  'cafe_user',

    getToken()  { return sessionStorage.getItem(this.TOKEN_KEY); },
    getUser()   { const u = sessionStorage.getItem(this.USER_KEY); return u ? JSON.parse(u) : null; },
    isLogged()  { return !!this.getToken(); },

    save(token, user) {
        sessionStorage.setItem(this.TOKEN_KEY, token);
        sessionStorage.setItem(this.USER_KEY, JSON.stringify(user));
    },

    clear() {
        sessionStorage.removeItem(this.TOKEN_KEY);
        sessionStorage.removeItem(this.USER_KEY);
    },

    /**
     * Retorna os headers corretos para cada tipo de requisição.
     * Requisições protegidas (escrita) incluem o JWT no header Authorization.
     */
    headers(isProtected = false) {
        const h = { 'Content-Type': 'application/json' };
        if (isProtected && this.getToken()) {
            h['Authorization'] = `Bearer ${this.getToken()}`;
        }
        return h;
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // Elementos do Modal de Login
    const loginOverlay   = document.getElementById('loginOverlay');
    const formLogin      = document.getElementById('formLogin');
    const loginError     = document.getElementById('loginError');
    const btnLogout      = document.getElementById('btnLogout');
    const jwtStatusBadge = document.getElementById('jwtStatusBadge');
    const jwtStatusText  = document.getElementById('jwtStatusText');

    // =========================================================================
    // SISTEMA DE LOGIN JWT
    // =========================================================================

    function updateAuthUI() {
        const user = Auth.getUser();
        if (Auth.isLogged() && user) {
            loginOverlay.classList.add('hidden');
            jwtStatusBadge.classList.add('authenticated');
            jwtStatusText.textContent = `${user.nome} (${user.perfil})`;
            btnLogout.style.display = 'flex';
        } else {
            loginOverlay.classList.remove('hidden');
            jwtStatusBadge.classList.remove('authenticated');
            jwtStatusText.textContent = 'Não Autenticado';
            btnLogout.style.display = 'none';
        }
    }

    // Checa se já existe sessão ativa ao carregar
    updateAuthUI();

    // Formulário de Login
    formLogin.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btnSubmit = document.getElementById('btnLoginSubmit');
        const usuario = document.getElementById('loginUsuario').value.trim();
        const senha   = document.getElementById('loginSenha').value;

        loginError.style.display = 'none';

        if (!usuario || !senha) {
            loginError.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Preencha usuário e senha.';
            loginError.style.display = 'flex';
            return;
        }

        btnSubmit.disabled = true;
        btnSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Autenticando...';

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ usuario, senha })
            });

            const data = await res.json();

            if (res.ok && data.success) {
                Auth.save(data.token, data.usuario);
                updateAuthUI();
                loadRecords();
            } else {
                loginError.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${data.error || 'Credenciais inválidas.'}`;
                loginError.style.display = 'flex';
            }
        } catch (err) {
            loginError.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Falha de conexão com o servidor.';
            loginError.style.display = 'flex';
        } finally {
            btnSubmit.disabled = false;
            btnSubmit.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Entrar no Sistema';
        }
    });

    // Logout
    btnLogout.addEventListener('click', async () => {
        try {
            await fetch('/api/auth/logout', {
                method: 'POST',
                headers: Auth.headers(true)
            });
        } catch (_) {}
        Auth.clear();
        document.getElementById('loginSenha').value = '';
        document.getElementById('loginUsuario').value = '';
        loginError.style.display = 'none';
        updateAuthUI();
    });


    const mainTabs = document.getElementById('mainTabs');
    const tabButtons = mainTabs.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const toastContainer = document.getElementById('toastContainer');

    const formPessoa = document.getElementById('formPessoa');
    const formProduto = document.getElementById('formProduto');

    const tablePessoasBody = document.querySelector('#tablePessoas tbody');
    const tableProdutosBody = document.querySelector('#tableProdutos tbody');

    // Stats
    const statPessoas = document.getElementById('statPessoas');
    const statProdutos = document.getElementById('statProdutos');
    const statEstoque = document.getElementById('statEstoque');
    const totalRecordsBadge = document.getElementById('totalRecordsBadge');

    // Botões de Refresh
    const btnRefreshPessoas = document.getElementById('btnRefreshPessoas');
    const btnRefreshProdutos = document.getElementById('btnRefreshProdutos');

    // =========================================================================
    // 1. SISTEMA DE NAVEGAÇÃO POR ABAS
    // =========================================================================
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.dataset.tab;

            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            button.classList.add('active');
            const targetEl = document.getElementById(targetTab);
            if (targetEl) targetEl.classList.add('active');

            if (targetTab === 'tab-registros') {
                loadRecords();
            }
        });
    });

    // =========================================================================
    // 2. APLICAÇÃO DE MÁSCARAS E VALIDAÇÃO EM TEMPO REAL
    // =========================================================================
    const allInputs = document.querySelectorAll('input, select, textarea');

    allInputs.forEach(input => {
        // Evento de Digitação: Aplica Máscara, Atualiza Contador e Valida
        input.addEventListener('input', () => {
            applyMask(input);
            window.ValidationEngine.updateCharCounter(input);
            window.ValidationEngine.validateField(input);
        });

        // Evento de Alteração de Estado (importante para checkboxes e selects)
        input.addEventListener('change', () => {
            window.ValidationEngine.validateField(input);
        });

        // Evento de Saída (Blur)
        input.addEventListener('blur', () => {
            window.ValidationEngine.validateField(input);
        });
    });

    function applyMask(input) {
        const securityType = input.dataset.securityType;
        const startPos = input.selectionStart;

        if (securityType === 'mask-cpf') {
            input.value = window.Masks.cpf(input.value);
        } else if (securityType === 'mask-phone') {
            input.value = window.Masks.phone(input.value);
        } else if (securityType === 'mask-currency') {
            input.value = window.Masks.currency(input.value);
        } else if (securityType === 'mask-sku') {
            input.value = window.Masks.sku(input.value);
        }
    }


    // =========================================================================
    // 4. SUBMISSÃO DOS FORMULÁRIOS (SUBMIT HANDLERS)
    // =========================================================================

    // Cadastrar Pessoa
    formPessoa.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const isFormValid = window.ValidationEngine.validateForm(formPessoa);
        if (!isFormValid) {
            showToast("Verifique os campos destacados em vermelho antes de prosseguir.", "error");
            return;
        }

        const formData = {
            nome: document.getElementById('pessoaNome').value,
            cpf: document.getElementById('pessoaCpf').value,
            email: document.getElementById('pessoaEmail').value,
            telefone: document.getElementById('pessoaTelefone').value,
            tipo: document.getElementById('pessoaTipo').value
        };

        try {
            const response = await fetch('/api/pessoas', {
                method: 'POST',
                headers: Auth.headers(true),
                body: JSON.stringify(formData)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                showToast(`Pessoa "${formData.nome}" cadastrada com sucesso!`, "success");
                formPessoa.reset();
                resetFormValidationState(formPessoa);
                loadRecords();
            } else {
                showToast(result.error || "Erro ao cadastrar pessoa.", "error");
            }
        } catch (err) {
            console.error("Erro na requisição:", err);
            showToast("Falha na comunicação com o servidor Node.js.", "error");
        }
    });

    // Cadastrar Produto
    formProduto.addEventListener('submit', async (e) => {
        e.preventDefault();

        const isFormValid = window.ValidationEngine.validateForm(formProduto);
        if (!isFormValid) {
            showToast("Verifique os campos destacados em vermelho antes de prosseguir.", "error");
            return;
        }

        const rawPreco = document.getElementById('prodPreco').value;
        const precoNum = window.Masks.currencyToNumber(rawPreco);

        const formData = {
            nome: document.getElementById('prodNome').value,
            categoria: document.getElementById('prodCategoria').value,
            preco: precoNum,
            sku: document.getElementById('prodSku').value,
            estoque: parseInt(document.getElementById('prodEstoque').value, 10),
            descricao: document.getElementById('prodDescricao').value
        };

        try {
            const response = await fetch('/api/produtos', {
                method: 'POST',
                headers: Auth.headers(true),
                body: JSON.stringify(formData)
            });

            const result = await response.json();

            if (response.ok && result.success) {
                showToast(`Produto "${formData.nome}" adicionado ao menu!`, "success");
                formProduto.reset();
                resetFormValidationState(formProduto);
                loadRecords();
            } else {
                showToast(result.error || "Erro ao cadastrar produto.", "error");
            }
        } catch (err) {
            console.error("Erro na requisição:", err);
            showToast("Falha na comunicação com o servidor Node.js.", "error");
        }
    });

    function resetFormValidationState(formEl) {
        const inputs = formEl.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.classList.remove('is-valid', 'is-invalid');
            window.ValidationEngine.updateCharCounter(input);
        });
    }

    // =========================================================================
    // 5. CARREGAMENTO E EXIBIÇÃO DE REGISTROS (TABELA + STATS)
    // =========================================================================
    async function loadRecords() {
        try {
            // Fetch Pessoas
            const resPessoas = await fetch('/api/pessoas');
            const dataPessoas = await resPessoas.json();
            
            // Fetch Produtos
            const resProdutos = await fetch('/api/produtos');
            const dataProdutos = await resProdutos.json();

            // Fetch Stats
            const resStats = await fetch('/api/stats');
            const dataStats = await resStats.json();

            if (dataPessoas.success) renderPessoasTable(dataPessoas.data);
            if (dataProdutos.success) renderProdutosTable(dataProdutos.data);

            if (dataStats) {
                statPessoas.textContent = dataStats.totalPessoas || 0;
                statProdutos.textContent = dataStats.totalProdutos || 0;
                statEstoque.textContent = dataStats.totalEstoque || 0;
                totalRecordsBadge.textContent = (dataStats.totalPessoas || 0) + (dataStats.totalProdutos || 0);
            }
        } catch (err) {
            console.error("Erro ao carregar dados do servidor:", err);
        }
    }

    function renderPessoasTable(list) {
        if (!list || list.length === 0) {
            tablePessoasBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-dim);">Nenhuma pessoa cadastrada ainda.</td></tr>`;
            return;
        }

        tablePessoasBody.innerHTML = list.map(p => `
            <tr>
                <td><strong>${escapeHtml(p.nome)}</strong></td>
                <td><code>${escapeHtml(p.cpf)}</code></td>
                <td>${escapeHtml(p.email)}</td>
                <td>${escapeHtml(p.telefone)}</td>
                <td><span class="type-pill">${escapeHtml(p.tipo)}</span></td>
                <td>
                    <button class="btn-danger-icon btn-delete-pessoa" data-id="${p.id}" onclick="deletePessoa('${p.id}')" title="Excluir Registro">
                        <i class="fa-solid fa-trash-can" style="pointer-events: none;"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    function renderProdutosTable(list) {
        if (!list || list.length === 0) {
            tableProdutosBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-dim);">Nenhum produto cadastrado no menu.</td></tr>`;
            return;
        }

        tableProdutosBody.innerHTML = list.map(p => `
            <tr>
                <td><code>${escapeHtml(p.sku)}</code></td>
                <td><strong>${escapeHtml(p.nome)}</strong></td>
                <td><span class="type-pill">${escapeHtml(p.categoria)}</span></td>
                <td><span class="price-tag">R$ ${p.preco.toFixed(2).replace('.', ',')}</span></td>
                <td>${p.estoque} un.</td>
                <td>
                    <button class="btn-danger-icon btn-delete-produto" data-id="${p.id}" onclick="deleteProduto('${p.id}')" title="Excluir Produto">
                        <i class="fa-solid fa-trash-can" style="pointer-events: none;"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    let isBusyDeleting = false;

    // Delegação de eventos nas tabelas (suporta tanto clique direto quanto bloqueios restritivos de CSP inline)
    tablePessoasBody.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-delete-pessoa');
        if (btn) {
            const id = btn.getAttribute('data-id');
            if (id && !isBusyDeleting) deletePessoa(id);
        }
    });

    tableProdutosBody.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-delete-produto');
        if (btn) {
            const id = btn.getAttribute('data-id');
            if (id && !isBusyDeleting) deleteProduto(id);
        }
    });

    // Exclusão de Pessoa via API
    window.deletePessoa = async function(id) {
        if (isBusyDeleting) return;
        if (!Auth.isLogged()) {
            showToast("Autenticação necessária para excluir registros.", "error");
            loginOverlay.classList.remove('hidden');
            return;
        }
        if (!confirm("Deseja realmente remover esta pessoa?")) return;

        isBusyDeleting = true;
        try {
            const res = await fetch(`/api/pessoas/${id}`, {
                method: 'DELETE',
                headers: Auth.headers(true)
            });
            const data = await res.json();
            if (res.ok && data.success) {
                showToast("Pessoa removida com sucesso.", "info");
                loadRecords();
            } else {
                if (res.status === 401) {
                    showToast("Sessão expirada. Faça login novamente.", "error");
                    Auth.clear();
                    updateAuthUI();
                } else {
                    showToast(data.error || "Erro ao excluir pessoa.", "error");
                }
            }
        } catch (err) {
            showToast("Erro de conexão ao excluir pessoa.", "error");
        } finally {
            setTimeout(() => { isBusyDeleting = false; }, 300);
        }
    };

    // Exclusão de Produto via API
    window.deleteProduto = async function(id) {
        if (isBusyDeleting) return;
        if (!Auth.isLogged()) {
            showToast("Autenticação necessária para excluir produtos.", "error");
            loginOverlay.classList.remove('hidden');
            return;
        }
        if (!confirm("Deseja realmente remover este produto do menu?")) return;

        isBusyDeleting = true;
        try {
            const res = await fetch(`/api/produtos/${id}`, {
                method: 'DELETE',
                headers: Auth.headers(true)
            });
            const data = await res.json();
            if (res.ok && data.success) {
                showToast("Produto removido com sucesso.", "info");
                loadRecords();
            } else {
                if (res.status === 401) {
                    showToast("Sessão expirada. Faça login novamente.", "error");
                    Auth.clear();
                    updateAuthUI();
                } else {
                    showToast(data.error || "Erro ao excluir produto.", "error");
                }
            }
        } catch (err) {
            showToast("Erro de conexão ao excluir produto.", "error");
        } finally {
            setTimeout(() => { isBusyDeleting = false; }, 300);
        }
    };

    if (btnRefreshPessoas) btnRefreshPessoas.addEventListener('click', loadRecords);
    if (btnRefreshProdutos) btnRefreshProdutos.addEventListener('click', loadRecords);

    // =========================================================================
    // 6. SISTEMA DE NOTIFICAÇÕES (TOAST) & ESCAPE HTML (XSS DEFENSE)
    // =========================================================================
    function showToast(message, type = "info") {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        let icon = "fa-circle-info";
        if (type === "success") icon = "fa-circle-check";
        if (type === "error") icon = "fa-triangle-exclamation";

        toast.innerHTML = `
            <i class="fa-solid ${icon}"></i>
            <span>${message}</span>
        `;

        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(20px)';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Inicialização
    loadRecords();
});
