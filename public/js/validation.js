/**
 * Motor de Validação de Formulários & Informações do Inspetor de Segurança
 */

const SecurityExplanations = {
    "maxlength-required": {
        field: "Nome / Texto Geral",
        securityTag: "Buffer Overflow & DoS",
        uxTag: "Prevenção de Truncamento",
        securityDesc: "O atributo <code>maxlength</code> limita o tamanho máximo do buffer enviado pela aplicação. Isso impede ataques onde vetores maliciosos enviam dados gigantescos (gigabytes) para travar o consumo de memória do servidor ou estourar colunas de banco de dados.",
        uxDesc: "Fornece um indicador numérico dos caracteres restantes em tempo real, informando visualmente os limites antes que a digitação seja bloqueada."
    },
    "mask-cpf": {
        field: "CPF do Cliente/Funcionário",
        securityTag: "Sanitização & Injection",
        uxTag: "Formatagem Automática",
        securityDesc: "A máscara remove instantaneamente qualquer caractere não numérico. Isso bloqueia injeções de SQL (SQLi), tags de scripts (XSS) e aspas no momento da digitação. Além disso, o Front-End executa a checagem algorítmica do Dígito Verificador (Módulo 11).",
        uxDesc: "Insere a pontuação padrão (<code>000.000.000-00</code>) automaticamente. O usuário não precisa se preocupar com pontos ou traços."
    },
    "typed-email": {
        field: "E-mail de Contato",
        securityTag: "Tipagem HTML5 & Rejeição Prévia",
        uxTag: "Teclado Mobile & Autofill",
        securityDesc: "Utilizar <code>type=\"email\"</code> faz o navegador validar estritamente a sintaxe (existência de @ e domínio) antes da submissão, reduzindo tráfego com dados inválidos.",
        uxDesc: "Dispositivos móveis abrem automaticamente o teclado otimizado com teclas rápidas para <code>@</code> e <code>.com</code>."
    },
    "mask-phone": {
        field: "Telefone / WhatsApp",
        securityTag: "Sanitização Numérica Estrita",
        uxTag: "Máscara Dinâmica DDD",
        securityDesc: "Bloqueia a entrada de letras e símbolos perigosos. Garante que apenas números com a extensão máxima de telefone brasileiro sejam aceitos.",
        uxDesc: "Muda dinamicamente o formato entre telefone fixo (8 dígitos) e celular (9 dígitos com DDD)."
    },
    "required-select": {
        field: "Seleção Obrigatória (Dropdown)",
        securityTag: "Consistência de Estado",
        uxTag: "Escolha Direcionada",
        securityDesc: "Garante que o estado da aplicação seja consistente e que uma opção válida seja explicitamente escolhida antes do processamento.",
        uxDesc: "Destaca o campo com contorno vermelho caso a seleção seja ignorada, direcionando o foco do usuário."
    },
    "mask-currency": {
        field: "Preço de Venda (R$)",
        securityTag: "Integridade Financeira",
        uxTag: "Padrão Monetário Nacional",
        securityDesc: "Converte e valida os valores para o padrão de centavos, prevenindo bugs de arredondamento de ponto flutuante e injeção de caracteres não financeiros.",
        uxDesc: "Exibe o prefixo R$ e formata centavos automaticamente conforme o usuário digita os números."
    },
    "mask-sku": {
        field: "Código SKU do Produto",
        securityTag: "Padronização de Chave Única",
        uxTag: "Auto-Caixa Alta",
        securityDesc: "Sanitiza o código identificador permitindo apenas caracteres alfanuméricos e hífens em maiúsculo, evitando chaves duplicadas por sensibilidade de caixa.",
        uxDesc: "Força caixa alta automaticamente, poupando a necessidade de acionar a tecla Caps Lock."
    },
    "typed-number": {
        field: "Quantidade de Estoque",
        securityTag: "Validação de Limites Mínimo/Máximo",
        uxTag: "Teclado Numérico Direct",
        securityDesc: "Valida os limites inteiros positivos via <code>type=\"number\"</code> com <code>min=\"0\"</code>, impedindo estoques negativos ou valores decimais inconsistentes.",
        uxDesc: "Permite usar os seletores numéricos (spinners) do browser para ajustar a quantidade rapidamente."
    },
    "maxlength-text": {
        field: "Descrição do Produto",
        securityTag: "Controle de Payload Longo",
        uxTag: "Contador de Caracteres Amplo",
        securityDesc: "Controla áreas de texto livre (textarea), prevenindo que descrições gigantescas ultrapassem os limites de armazenamento alocados no banco.",
        uxDesc: "Dá visibilidade instantânea de quantos caracteres de detalhes ainda podem ser adicionados."
    },
    "required-checkbox": {
        field: "Termos de Uso & Consentimento",
        securityTag: "Não-Repúdio & Compliance",
        uxTag: "Transparência & Acessibilidade",
        securityDesc: "Exigir o aceite explícito dos termos garante conformidade com leis de proteção de dados (como LGPD) e estabelece o princípio de não-repúdio, comprovando que o usuário consentiu com as regras de negócio e políticas de privacidade antes do processamento dos dados.",
        uxDesc: "Informa claramente ao usuário seus direitos e obrigações através de um link direto para os termos. A validação visual destaca a caixa de seleção e impede o envio sem o consentimento intencional."
    }
};

const ValidationEngine = {
    // Atualiza contadores e avisa quando próximo do limite
    updateCharCounter(inputEl) {
        const fieldId = inputEl.id;
        const counterEl = document.getElementById(`cnt-${fieldId}`);
        if (!counterEl) return;

        const currentLen = inputEl.value.length;
        const maxLen = inputEl.getAttribute('maxlength');

        if (maxLen) {
            counterEl.textContent = `${currentLen} / ${maxLen}`;
            
            counterEl.classList.remove('limit-near', 'limit-reached');
            if (currentLen >= parseInt(maxLen, 10)) {
                counterEl.classList.add('limit-reached');
            } else if (currentLen >= parseInt(maxLen, 10) * 0.85) {
                counterEl.classList.add('limit-near');
            }
        }
    },

    // Valida um campo individualmente
    validateField(inputEl) {
        const fieldId = inputEl.id;
        const errorEl = document.getElementById(`err-${fieldId}`);
        const fieldName = inputEl.dataset.fieldName || "Campo";
        let isValid = true;
        let errorMsg = "";

        // 1. Campo Obrigatório (Required)
        if (inputEl.hasAttribute('required')) {
            if (inputEl.type === 'checkbox' || inputEl.getAttribute('type') === 'checkbox') {
                if (!inputEl.checked) {
                    isValid = false;
                    errorMsg = `Você deve aceitar os ${fieldName}.`;
                }
            } else if (!inputEl.value || inputEl.value.trim() === "") {
                isValid = false;
                errorMsg = `${fieldName} é um campo obrigatório.`;
            }
        }

        // 2. Validação por Tipo de Input & Conteúdo (se preenchido e não for checkbox)
        if (isValid && inputEl.type !== 'checkbox' && inputEl.value.trim() !== "") {
            const inputType = inputEl.getAttribute('type');
            const securityType = inputEl.dataset.securityType;

            // E-mail
            if (inputType === 'email' || securityType === 'typed-email') {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(inputEl.value.trim())) {
                    isValid = false;
                    errorMsg = "Por favor, insira um e-mail válido (ex: nome@dominio.com).";
                }
            }

            // CPF
            if (securityType === 'mask-cpf') {
                if (inputEl.value.length < 14) {
                    isValid = false;
                    errorMsg = "CPF incompleto (deve conter 11 dígitos).";
                } else if (!window.Masks.isValidCPF(inputEl.value)) {
                    isValid = false;
                    errorMsg = "CPF inválido (falha no dígito verificador).";
                }
            }

            // Telefone
            if (securityType === 'mask-phone') {
                if (inputEl.value.length < 14) { // Mínimo (81) 0000-0000
                    isValid = false;
                    errorMsg = "Telefone incompleto (informe DDD + Número).";
                }
            }

            // Moeda / Preço
            if (securityType === 'mask-currency') {
                const numVal = window.Masks.currencyToNumber(inputEl.value);
                if (numVal <= 0) {
                    isValid = false;
                    errorMsg = "O preço deve ser superior a R$ 0,00.";
                }
            }

            // Número / Estoque
            if (inputType === 'number' || securityType === 'typed-number') {
                const val = parseInt(inputEl.value, 10);
                const min = parseInt(inputEl.getAttribute('min') || 0, 10);
                if (isNaN(val) || val < min) {
                    isValid = false;
                    errorMsg = `O valor deve ser um número maior ou igual a ${min}.`;
                }
            }
        }

        // Renderiza estado de erro no DOM
        if (errorEl) {
            errorEl.textContent = errorMsg;
        }

        if (isValid) {
            inputEl.classList.remove('is-invalid');
            inputEl.classList.add('is-valid');
        } else {
            inputEl.classList.remove('is-valid');
            inputEl.classList.add('is-invalid');
        }

        return isValid;
    },

    // Valida todo o formulário antes de enviar
    validateForm(formEl) {
        const inputs = formEl.querySelectorAll('input, select, textarea');
        let formValid = true;

        inputs.forEach(input => {
            const isInputValid = this.validateField(input);
            if (!isInputValid) {
                formValid = false;
            }
        });

        return formValid;
    }
};

window.SecurityExplanations = SecurityExplanations;
window.ValidationEngine = ValidationEngine;
