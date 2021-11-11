<?php
if(isset($_GET['ver'])){echo 'version:2.2 190713';exit;}

date_default_timezone_set("Asia/Shanghai");
define('ALPHABET', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
$encrypt_page=true;
$gzip_page=true;
$mirror = 'jyg-com2.appspot.com';
$enablecache=false;#服务端缓存开关
$cachepath='./cache/';#缓存目录
$cachelife=28800;#服务器端缓存文件周期(默认一天），单位为秒
$cli_cache=false; #浏览器缓存开关
$client_life=3600;#客户端（浏览器）缓存文件周期，单位为秒
$nocache=array();#缓存排除数组列表

function utf2html($str){
    $ret='';
    $max=strlen($str);
    $last=0;
    for ($i=0;$i < $max;$i++){
        $c=$str{$i};
        $c1=ord($c);
        if ($c1 >> 5 == 6){
            $ret .= substr($str, $last, $i - $last);
            $c1 &= 31; # remove the 3 bit two bytes prefix
            $c2=ord($str{++$i});
            $c2 &= 63;
            $c2 |= (($c1 & 3) << 6);
            $c1 >>= 2;
            $ret .= '&#' . ($c1 * 0x100 + $c2) . ';';
            $last=$i + 1;
            }
        elseif ($c1 >> 4 == 14){
            $ret .= substr($str, $last, $i - $last);
            $c2=ord($str{++$i});
            $c3=ord($str{++$i});
            $c1 &= 15;
            $c2 &= 63;
            $c3 &= 63;
            $c3 |= (($c2 & 3) << 6);
            $c2 >>= 2;
            $c2 |= (($c1 & 15) << 4);
            $c1 >>= 4;
            $ret .= '&#' . (($c1 * 0x10000) + ($c2 * 0x100) + $c3) . ';';
            $last=$i + 1;
            }
        }
    $str=$ret . substr($str, $last, $i);
    return $str;
}
function code($w,$k,$d) {
	if ($w=='decrypt'){$d=base64_decode(strtr($d,$k,ALPHABET.'+/'));}
	if ($w=='encrypt'){$d=strtr(rtrim(base64_encode($d),'='),ALPHABET.'+/',$k);}
	return $d;
}
function encodePage($input) {
	$parts=array();
	if(preg_match('#^(.*?)<head[^>]*>(.*?)</head>\s*<body([^>]*)>(.*)</body>(.*?)</html>(.*)$#is',$input,$parts)){
		unset($parts[0]);
		$meta1=preg_match('#\s?<meta.+?charset=[^\w]?([-\w]+)[^>]+>\s?#is',$parts[2],$tmp)?$tmp[0]:null;
		$meta2=preg_match('#<meta http-equiv="X-UA-Compatible".+?content=[^\w]?([=\w]+)[^>]+>\s?#i',$parts[2],$tmp)?$tmp[0]:null;
		$parts[1].="<head>\n".$meta1.$meta2.injectionJS();
		$parts[2]=str_replace(array($meta1,$meta2),'',$parts[2]);
		$parts[2]=encodeBlock($parts[2])."\n</head>";
		$parts[3]="\n<body{$parts[3]}>\n";
		$parts[4]=encodeBlock($parts[4])."\n</body>";
		$parts[5]=encodeBlock($parts[5])."\n</html>\n";
		#$parts[6]=encodeBlock($parts[6]);
	}else return $input; #明慧部分网页不能正确匹配，直接返回input。
	return implode('',$parts);
}
function encodeBlock($input) {
	global $psd,$dec;
	if(empty($input))return '';
	return '<script type="text/javascript">document.write('.$dec.'(\''.code('encrypt',$psd,$input) .'\'));</script>';
}
function injectionJS() {
	global $psd,$dec;
	return <<<OUT
<script type="text/javascript">function {$dec}(d){var q='{$psd}';var z,y,x,w,v,u,t,s,p=d.length,i=0,j=0,r=[];do{w=q.indexOf(d.charAt(i++));v=q.indexOf(d.charAt(i++));u=q.indexOf(d.charAt(i++));t=q.indexOf(d.charAt(i++));s=w<<18|v<<12|u<<6|t;z=s>>16&0xff;y=s>>8&0xff;x=s&0xff;r[j++]=String.fromCharCode(z,y,x);}while(i<p);return r.join('');}</script>
OUT;
}
function checkDir($path, $htaccess=false) {
	if($path=='/')return true;
	if ( file_exists($path) ) {
		if ( is_writable($path) ) {
			return 'ok';
		}
		return false;
	} else {
		if (is_writable('./') && mkdir($path, 0777, true) ) {
			if ( $htaccess ) {
				file_put_contents($path . '/.htaccess', $htaccess);
			}
			return 'made';
		}
	}
	return false;
}

$contents='';
$mime0='';
$filexit=false;
$types=array(
		'html'	=>	'text/html; charset=UTF-8',
		'htm'	=>	'text/html; charset=UTF-8',
		'js'	=>	'text/javascript; charset=UTF-8',
		'css'	=>	'text/css; charset=UTF-8',
		'rss'	=>	'text/xml; charset=UTF-8',
		'zip'	=>	'application/zip',
		'jpg'	=>	'image/jpeg',
		'jpeg'	=>	'image/jpeg',
		'gif'	=>	'image/gif',
		'png'	=>	'image/png',
		'exe'	=>	'application/x-msdownload',
		'apk'	=>	'application/vnd.android.package-archive',
		'flv'	=>	'video/x-flv',
		'mp4'	=>	'video/mp4',
		'binary'	=>	'application/octet-stream',
		);

if(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && $_SERVER['REQUEST_TIME']-strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE'].' +8 hours')<$client_life){
	header("HTTP/1.1 304 Not Modified", true, 304);exit;
}
if($enablecache){
	if(preg_match('#((.*/)([^/\?]*))\??(.*)#i',$_SERVER['REQUEST_URI'],$pathinfo)){
		$pathinfo[2]=empty($pathinfo[2])?$cachepath:$cachepath.$pathinfo[2];
		$cachefile=empty($pathinfo[3])?$cachepath.$pathinfo[1].'/index.html':(strpos($pathinfo[3],'.')?$cachepath.$pathinfo[1]:$cachepath.$pathinfo[1].'.html');
		$cachefile=empty($pathinfo[4])?$cachefile:str_replace('.html',str_replace('=','_',$pathinfo[4]).'.html',$cachefile);
		$cachefile=str_replace('//','/',$cachefile);
		if(file_exists($cachefile)){
			$filexit=true;
			if($_SERVER['REQUEST_TIME']-filemtime($cachefile)<$cachelife){
				$contents=file_get_contents($cachefile);
			}
		}
	}
}
if(!empty($contents)){
	$doc=$contents;
}else{
	$req = $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . " HTTP/1.0\r\n";
	$length = 0;
	foreach ($_SERVER as $k => $v) {
		if (substr($k, 0, 5) == "HTTP_") {
			$k = str_replace('_', ' ', substr($k, 5));
			$k = str_replace(' ', '-', ucwords(strtolower($k)));
			if ($k == "Host")
				$v = $mirror;						# Alter "Host" header to mirrored server
			if ($k == "Accept-Encoding")
				$v = "identity;q=1.0, *;q=0";		# Alter "Accept-Encoding" header to accept unencoded content only
			if ($k == "Keep-Alive")
				continue;							# Drop "Keep-Alive" header
			if ($k == "Connection" && $v == "keep-alive")
				$v = "close";						# Alter value of "Connection" header from "keep-alive" to "close"
			$req .= $k . ": " . $v . "\r\n";
		}
	}
	$body = @file_get_contents('php://input');
	$req .= "Content-Type: " . $_SERVER['CONTENT_TYPE'] . "\r\n";
	$req .= "Content-Length: " . strlen($body) . "\r\n";
	$req .= "\r\n";
	$req .= $body;

	#print $req;

	$fp = fsockopen($mirror, 80, $errno, $errmsg, 30);
	if (!$fp) {
		print "HTTP/1.0 502 Failed to connect remote server\r\n";
		print "Content-Type: text/html\r\n\r\n";
		print "<html><body>Failed to connect to $mirror due to:<br>[$errno] $errstr</body></html>";
		exit;
	}

	fwrite($fp, $req);

	$headers_processed = 0;
	$reponse = '';
	$doc='';
	while (!feof($fp)) {
		$r = fread($fp, 8192);
		if (!$headers_processed) {
			$response = $r;
			$nlnl = strpos($response, "\r\n\r\n");
			$add = 4;
			if (!$nlnl) {
				$nlnl = strpos($response, "\n\n");
				$add = 2;
			}
			if (!$nlnl)
				continue;
			$headers = substr($response, 0, $nlnl);
			if (preg_match_all('/^(.*?)(\r?\n|$)/ims', $headers, $matches))
				for ($i = 0; $i < count($matches[0]); ++$i) {
					if ($filexit && stripos($matches[1][$i],'Last-Modified') !==false && filemtime($cachefile)>strtotime(substr($matches[1][$i],15))) {
						$doc=file_get_contents($cachefile);
						break 2;
					}
					if (stripos($matches[1][$i],'Content-Length') ===false ) {
						$ct = $matches[1][$i];
					}
					if (stripos($matches[1][$i],'Content-Type') ===0 ) {
						$mime0=$matches[1][$i];
						$charset=stripos($matches[1][$i],'charset')?substr($matches[1][$i],stripos($matches[1][$i],'charset')+8):null;
					}
					header($ct, false);
				}
			$doc.=substr($response, $nlnl + $add);
			$headers_processed = 1;
		} else
			$doc.=$r;
	}
	fclose ($fp);

	if($mime0 && strpos($headers,' 200 OK')){
		if (!isset($charset)) {
			$charset = preg_match('/<meta.+?charset=[^\w]?([-\w]+)/i',$doc,$tmp)?$tmp[1]:null;
		}
		$doc=str_replace($mirror,$_SERVER['SERVER_NAME'],$doc);
		if (isset($charset)) {
			if (function_exists('mb_convert_encoding')) {
				$doc=mb_convert_encoding($doc, 'HTML-ENTITIES', $charset);
			}else{
				$doc = iconv($charset, 'UTF-8//IGNORE//TRANSLIT', $doc);
				$doc = utf2html($doc);
			}
			if($encrypt_page){
				$psd=substr(str_shuffle(ALPHABET.'+/`~!@$^*_-|;:?,.'),0,64);
				$dec='_'.substr(str_shuffle(ALPHABET),0,4);
				$doc=encodePage($doc);
			}
		}
		if($enablecache && !empty($doc) && !in_array($_SERVER['REQUEST_URI'],$nocache)){
			if(checkDir($pathinfo[2])){
				if($f=fopen($cachefile,'wb')){
					flock($f,LOCK_EX);
					fwrite($f,$doc);
					flock($f,LOCK_UN);
					fclose($f);
				}
			}
			#file_put_contents($cachefile,$doc,LOCK_EX);
		}
	}else{
		if($filexit){
			$doc=file_get_contents($cachefile);
		}
	}
}
if ($gzip_page && isset($_SERVER['HTTP_ACCEPT_ENCODING']) && strpos($_SERVER['HTTP_ACCEPT_ENCODING'],'gzip') !== false && extension_loaded('zlib') && ! ini_get('zlib.output_compression')) {
	$doc=gzencode($doc, 6);
	header('Content-Encoding: gzip');
	header('Vary: Accept-Encoding');
	header('Content-Length: '.strlen($doc));
}
if($filexit){
	if($type=$types[pathinfo($cachefile, PATHINFO_EXTENSION)]){
		header('Content-Type: '.$type);
	}else{
		header('Content-Type: '.$types['binary']);
	}
	if($cli_cache){
		header('Cache-Control: max-age='.$client_life.',must-revalidate');
		header('Last-Modified: '.gmdate('D, d M Y H:i:s \G\M\T',filemtime($cachefile)));
		header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T',$_SERVER['REQUEST_TIME']+$client_life));
	}
}
echo $doc;
?>
