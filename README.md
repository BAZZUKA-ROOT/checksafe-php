# 🔐 CheckSafe — Verificador de Segurança de Checkout

Ferramenta PHP para detectar fraudes em checkouts online — analisa dados suspeitos e envia alertas via Telegram.

![Language](https://img.shields.io/badge/Stack-PHP-purple) ![License](https://img.shields.io/badge/Licen%C3%A7a-MIT-blue)

---

## 🎯 O que faz

- Recebe dados de formulários de checkout
- Detecta padrões suspeitos (CPF inválido, email descartável, etc.)
- Notifica via Telegram em tempo real
- Painel admin para consultar o histórico
- Armazenamento local em JSON (sem banco de dados)

## ⚙️ Configuração

1. Copie `.env.example` para `.env` e preencha o token do Telegram
2. **Ou** edite `config.php` diretamente com suas credenciais
3. Suba para servidor PHP 7.4+

### Obter token Telegram

1. Crie um bot via [@BotFather](https://t.me/BotFather)
2. Copie o token gerado
3. Para obter seu `chat_id`, use [@userinfobot](https://t.me/userinfobot)

## 📂 Estrutura

```
checksafe-php/
├── index.php              # Interface principal
├── checksafe_core.php     # Lógica de verificação
├── admin_consultas.php    # Painel de consultas
├── config.php             # Configurações (token Telegram)
├── assets/                # CSS e JS
├── data/                  # Dados auxiliares
└── checksafe_storage/     # JSONs (ignorado pelo git)
```

## 🚀 Como usar

```bash
# Hospedar em qualquer servidor PHP
# Acessar index.php no navegador
```

## 📄 Licença

MIT

---
Feito com ☕ no Brasil 🇧🇷
