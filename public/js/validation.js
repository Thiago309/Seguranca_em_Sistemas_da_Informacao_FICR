/**
 * Motor de Validação de Formulários (Front-End)
 */

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

window.ValidationEngine = ValidationEngine;
