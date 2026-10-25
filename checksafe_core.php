<?php
function checksafe_secure_dir(): string {
    $dir = $GLOBALS['CHECKSAFE_DATA_DIR'] ?? (__DIR__ . '/checksafe_storage');
    $dir = rtrim((string)$dir, '/\\');
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $ht = $dir.'/.htaccess'; if (!is_file($ht)) @file_put_contents($ht, "Require all denied\nDeny from all\nOptions -Indexes\n");
    $idx = $dir.'/index.php'; if (!is_file($idx)) @file_put_contents($idx, "<?php http_response_code(403); exit('Acesso negado.');");
    $web = $dir.'/web.config'; if (!is_file($web)) @file_put_contents($web, "<?xml version=\"1.0\"?><configuration><system.webServer><security><requestFiltering><hiddenSegments><add segment=\"checksafe_storage\" /></hiddenSegments></requestFiltering></security></system.webServer></configuration>");
    return $dir;
}
function checksafe_settings_path(): string { return checksafe_secure_dir() . '/settings_' . substr(hash('sha256', __DIR__.'|settings'),0,16) . '.json'; }
function checksafe_default_settings(): array { return [
 'maintenance'=>['active'=>false,'title'=>'Site em manutenção','message'=>'Estamos realizando ajustes para melhorar sua experiência. Volte em instantes.'],
 'result_rules'=>['leak_percent'=>80,'min_occurrences'=>1,'max_occurrences'=>6],
 'form'=>['title'=>'Consulta de dados','subtitle'=>'Preencha as informações para fazer uma verificação.','button'=>'Verificar agora','fields'=>[
   ['name'=>'nome','label'=>'Nome completo','type'=>'text','placeholder'=>'Digite seu nome','required'=>true,'min'=>3],
   ['name'=>'cpf','label'=>'CPF','type'=>'text','placeholder'=>'000.000.000-00','required'=>true,'mask'=>'cpf'],
   ['name'=>'email','label'=>'E-mail','type'=>'email','placeholder'=>'email@exemplo.com','required'=>true],
   ['name'=>'telefone','label'=>'Telefone','type'=>'text','placeholder'=>'(00) 00000-0000','required'=>true,'mask'=>'telefone'],
   ['name'=>'cidade','label'=>'Cidade','type'=>'text','placeholder'=>'Digite sua cidade','required'=>false]
 ]],
 'companies'=>[
  ['data'=>'Jan 2023','tipo'=>'Loja online','nome'=>'AlphaStore Brasil','texto'=>'Base demonstrativa de loja virtual com informações básicas de cadastro e contato.','dados'=>['Nome completo','E-mail','Telefone']],
  ['data'=>'Jun 2024','tipo'=>'Pagamento','nome'=>'NetPay Serviços','texto'=>'Registro simulado de plataforma financeira com dados de identificação do usuário.','dados'=>['CPF','E-mail','Cidade']],
  ['data'=>'Set 2025','tipo'=>'Aplicativo','nome'=>'SocialLink App','texto'=>'Exemplo fictício de aplicativo social com exposição parcial de informações de contato.','dados'=>['Nome','Telefone']],
  ['data'=>'Dez 2025','tipo'=>'Nuvem','nome'=>'DataMail Cloud','texto'=>'Ocorrência demonstrativa de serviço em nuvem com cadastro localizado na análise.','dados'=>['E-mail','Identificador']],
  ['data'=>'Fev 2026','tipo'=>'Marketplace','nome'=>'Digital Market BR','texto'=>'Cadastro demonstrativo de marketplace com registros básicos de usuário.','dados'=>['Nome','CPF','E-mail']],
  ['data'=>'Abr 2026','tipo'=>'Telefonia','nome'=>'Connect Brasil','texto'=>'Base fictícia de serviço de comunicação com dados de contato vinculados ao cadastro.','dados'=>['Telefone','Cidade','E-mail']]
 ]
];}
function checksafe_load_settings(): array { $def=checksafe_default_settings(); $p=checksafe_settings_path(); if(is_file($p)){ $j=json_decode((string)@file_get_contents($p),true); if(is_array($j)){ $def=array_replace_recursive($def,$j); }} return $def; }
function checksafe_save_settings(array $s): bool { $j=json_encode($s,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); return $j!==false && @file_put_contents(checksafe_settings_path(),$j,LOCK_EX)!==false; }
function checksafe_slug_field(string $label): string { $base = iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$label); $base = strtolower(preg_replace('/[^a-zA-Z0-9]+/','_', (string)$base)); $base = trim($base,'_'); return $base ?: 'campo_'.substr(md5($label.microtime()),0,6); }
?>
