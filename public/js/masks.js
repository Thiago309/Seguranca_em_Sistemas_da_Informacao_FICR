/**
 * Módulos de Máscara e Sanitização de Entrada em Tempo Real
 * Garante padronização e impede digitação de caracteres especiais ou ilegais.
 */

const Masks = {
    // Máscara de CPF: 000.000.000-00
    cpf(value) {
        if (!value) return '';
        return value
            .replace(/\D/g, '') // Remove tudo que não for dígito (Sanitização)
            .replace(/(\d{3})(\d)/, '$1.$2')
            .replace(/(\d{3})(\d)/, '$1.$2')
            .replace(/(\d{3})(\d{1,2})$/, '$1-$2')
            .substring(0, 14); // Limite rígido
    },

    // Máscara de Telefone: (00) 00000-0000 ou (00) 0000-0000
    phone(value) {
        if (!value) return '';
        let digits = value.replace(/\D/g, '').substring(0, 11);
        if (digits.length <= 10) {
            return digits
                .replace(/^(\d{2})(\d)/, '($1) $2')
                .replace(/(\d{4})(\d)/, '$1-$2');
        } else {
            return digits
                .replace(/^(\d{2})(\d)/, '($1) $2')
                .replace(/(\d{5})(\d)/, '$1-$2');
        }
    },

    // Máscara de Moeda Brasileira: R$ 0,00
    currency(value) {
        if (!value) return '';
        let clean = value.replace(/\D/g, '');
        if (clean === '') return '';
        
        let number = (parseFloat(clean) / 100).toFixed(2);
        let parts = number.split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, '.');
        return `R$ ${parts.join(',')}`;
    },

    // Extrator de valor numérico limpo a partir de moeda R$
    currencyToNumber(currencyStr) {
        if (!currencyStr) return 0;
        let clean = currencyStr.replace('R$', '').replace(/\./g, '').replace(',', '.').trim();
        return parseFloat(clean) || 0;
    },

    // Máscara SKU (Auto-Uppercase + Hífens): EX: CAF-ESP-250
    sku(value) {
        if (!value) return '';
        return value
            .toUpperCase()
            .replace(/[^A-Z0-9-]/g, '') // Remove caracteres inválidos
            .substring(0, 15);
    },

    // Validador matemático de CPF real (Dígito Verificador Modulo 11)
    isValidCPF(cpfStr) {
        if (!cpfStr) return false;
        const cleanCPF = cpfStr.replace(/\D/g, '');
        if (cleanCPF.length !== 11) return false;
        if (/^(\d)\1{10}$/.test(cleanCPF)) return false; // Impede 111.111.111-11

        let sum = 0;
        let remainder;

        for (let i = 1; i <= 9; i++) {
            sum += parseInt(cleanCPF.substring(i - 1, i)) * (11 - i);
        }
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(cleanCPF.substring(9, 10))) return false;

        sum = 0;
        for (let i = 1; i <= 10; i++) {
            sum += parseInt(cleanCPF.substring(i - 1, i)) * (12 - i);
        }
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(cleanCPF.substring(10, 11))) return false;

        return true;
    }
};

// Export global window
window.Masks = Masks;
