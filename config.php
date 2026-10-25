<?php
// CONFIGURAÇÃO DO TELEGRAM
// Crie um bot via @BotFather e obtenha o token
// Para obter o chat_id, use @userinfobot ou @getidsbot

$TELEGRAM_BOT_TOKEN = getenv('TELEGRAM_BOT_TOKEN') ?: 'SEU_TOKEN_AQUI';
$TELEGRAM_CHAT_ID   = getenv('TELEGRAM_CHAT_ID') ?: 'SEU_CHAT_ID_AQUI';

// Modo seguro: envia dados mascarados (recomendado para estudos)
$MASCARAR_DADOS = true;

// Segurança do arquivo JSON de consultas
$CHECKSAFE_DATA_DIR = __DIR__ . '/checksafe_storage';
$CHECKSAFE_JSON_FILE = 'consultas_' . substr(hash('sha256', __DIR__ . '|checksafe-json'), 0, 16) . '.json';
$CHECKSAFE_ADMIN_SENHA = '123456'; // Troque por uma senha forte em produção.


// ==============================
// CHECKSAFE - CONFIGURAÇÕES DO PAINEL
// ==============================
function checksafe_storage_dir_config(): string {
    $dir = $GLOBALS['CHECKSAFE_DATA_DIR'] ?? (__DIR__ . '/checksafe_storage');
    return rtrim((string)$dir, '/\');
}
function checksafe_proteger_storage(): void {
    $dir = checksafe_storage_dir_config();
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $htaccess = $dir . '/.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "Deny from all\n");
    }
}
