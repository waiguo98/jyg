<?php

// �Ժ���ʹ�� Guzzle ��������

/**
* ��ҳ��ʵ�ֵļ�����
* Url url������
* FileLock ��ֹ�����ͻ���������ļ���
* CacheHttp HTTP���ݵ��ļ�������
* Http �����ʹ�ò�ͬ����ʵ��HTTP����ļ��������ࣨHttpFsockopen HttpCurl HttpFopen��
*
* ��PHPʵ�ֵ�ȫ���� Http Client ��(����php5�²��ԣ�δ��php4�²���)
* 1. ��PHP����ʵ�֣�ֻʹ��php����ģ��ͺ������������κ����������������չ
* 2. ���Ը��ݷ�������������3��ʵ�ַ�����pfsockopen��fsockopen��cUrl��fopen�����Զ�ѡ����õģ�ÿ�ַ�����ʹ��һ��������������ʵ��
* 3. �����û��ȡ���е�HTTPͷ
* 4. ����ȫ���ܲ��Ҵ���һ�����ܵ�COOKIE����
* 5. ��ɹ��һ���ǣ�֧�� Keep-Alive ��HTTP���ӣ��ر��ʺ�һ����������������ͬһ�������������
* 6. ֧��ͨ��POST��ʽ�ϴ�������ļ������������ֶε�
* 7. ֧��SSL
* 8. ������ is_utf8 �� mb_convert_encoding ����ʱ������url���ܱ���������
*
*/

defined('HTTP_INC_LOADED') or define('HTTP_INC_LOADED', 1);
//Ӧ�õ���ʱĿ¼�����������뱾�ļ�֮ǰʹ���������ͳһȷ����ʱ�ļ��е�λ�ã�
defined('TEMPDIR') or define('TEMPDIR', dirname(__FILE__).'/temp');
//HTTP������ೢ�Դ���
define ('HTTP_MAX_RETRIES', 3);
//�Ƿ����ó�����
define ('PERSISTENT_CONNECTION', 1);
//���ջ�������С
define('HTTP_BUFFERING', 4096);
//��ǰʱ��
defined('TIME') or define('TIME', time());
defined('TODAY') or define('TODAY', date('d',TIME));
//�Ƿ��ֹ��set_time_limit����
define('ENABLE_SET_TIME_LIMIT', function_exists('set_time_limit'));
//��������http������Ӧ
$last_http_error = null;

/* ���������Ӧ���Ѿ��жϹ���
if(version_compare(PHP_VERSION, '5.3.3', '<')){
	exit('Need PHP 5.3.3 or higher!');
}
*/


/**
 * ��ѹ����
 * @param string $data
 * @return string
 */
function my_gzdecode($data) {
	if (strlen($data)<18 || strcmp(substr($data,0,2),"\x1f\x8b")) {
		return false;  // Not GZIP format (See RFC 1952)
	}
	if (function_exists('gzdecode') && ($unpacked=gzdecode($data))){
		return $unpacked;
	}
	if (!function_exists('gzinflate')){
		return false;
	}
	$flags = ord ( substr ( $data, 3, 1 ) );
	$headerlen = 10;
	$extralen = 0;
	$filenamelen = 0;
	if ($flags & 4) {
		$extralen = unpack ( v, substr ( $data, 10, 2 ) );
		$extralen = $extralen [1];
		$headerlen += 2 + $extralen;
	}
	if ($flags & 8) // Filename
		$headerlen = strpos ( $data, chr ( 0 ), $headerlen ) + 1;
	if ($flags & 16) // Comment
		$headerlen = strpos ( $data, chr ( 0 ), $headerlen ) + 1;
	if ($flags & 2) // CRC at end of file
		$headerlen += 2;
	$unpacked = gzinflate ( substr ( $data, $headerlen ) );
	return $unpacked;
}

if(!function_exists('mkdirs')){
	/**
	 * �ݹ鴴��Ŀ¼
	 */
	function mkdirs($dir, $mode = 0775)
	{
		if (empty($dir)){
			return false;
		}elseif(is_dir($dir)) {
			return true;
		} else {
			$parent = dirname($dir);
			if (is_dir($parent)) {
				return mkdir($dir, $mode) && chmod($dir, $mode);
			} else {
				return mkdirs($parent, $mode) && mkdir($dir, $mode) && chmod($dir, $mode);
			}
		}
	}
}

if(!function_exists('fileext')){
	/**
	 * ��ȡ�ļ���չ��(����.)
	 */
	function fileext($filename){
		return (preg_match('#^[^\?&]+?(\.[~\w\-]+)(?:\?|\#|$)#S', $filename, $m)) ? strtolower($m[1]) : '';
	}
}

if(!function_exists('curl_setopt_array') && function_exists('curl_setopt')) {
	function curl_setopt_array($ch, $options) {
		foreach($options as $k=>$v) {
			curl_setopt($ch, $k, $v);
		}
	}
}

/**
 * ����url�ĸ�������
 */
class Url{
	//�� http://username:password@hostname:8000/path/script?name=value#top Ϊ������������£�
	public $original;  	//ʵ�������ԭʼurl
	public $scheme; //Э�� http
	public $host; 	//���� hostname
	public $port; 	//�˿� 8000
	public $site;	//�������ͷ�Ĭ�϶˿� hostname:8000
	public $user; 	//�û��� username
	public $pass; 	//���� password
	public $path; 	//·�� /php/
	public $query;	//���� name=project
	public $fragment;	//#֮��Ĳ��� top
	public $home;   //��ҳ��ַ http://localhost:8080
	public $script; //�ļ�����·�� /php/user.php
	public $file;   //�ļ������� user.php
	public $uri;	//·���Ͳ��� /php/user.php?name=project
	public $url;  	//����url������������·���������ȣ����ǲ�����#������ݣ�
	private $defaultPorts = array('https'=>443, 'http'=>80, 'ftp'=>21,);

	public static function getCurrentScheme(){
		if(isset($_SERVER['REQUEST_SCHEME'])){
			return $_SERVER['REQUEST_SCHEME'];
		}elseif(isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && ($_SERVER['HTTP_X_FORWARDED_PROTO']=='http' || $_SERVER['HTTP_X_FORWARDED_PROTO']=='http')){
			return $_SERVER['HTTP_X_FORWARDED_PROTO'];
		}elseif((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']=='on') || (isset($_ENV['HTTPS']) && $_ENV['HTTPS']=='on') || $_SERVER['SERVER_PORT']==443){
			return 'https';
		}else{
			return 'http';
		}
	}

	public static function getCurrentSite(){
		if(isset($_SERVER['HTTP_HOST'])){
			return $_SERVER['HTTP_HOST'];
		}else{
			$serverName = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
			return in_array($_SERVER['SERVER_PORT'], array(80,443)) ? $serverName : "{$serverName}:{$_SERVER['SERVER_PORT']}";
		}
	}

	/**
	 * ��ǰ��ҳ������url (���������صĲ���α��̬��ַ�����Ƕ�̬��ַȥ��Ĭ�ϵ�index.php�Ĳ��֣�ʵ����ֻʹ�����ı���·��֮ǰ���ֵ�����)
	 * @return Url ���ص�ǰurl��Url����
	 */
	public static function getCurrentUrl(){
		$url = self::getCurrentScheme() . '://' . self::getCurrentSite();
		$url .= isset($_SERVER['PHP_SELF']) ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];
		if(substr($url,-10)=='/index.php') $url=substr($url,0,-9);
		if(isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING']){
			$url .= '?'.$_SERVER['QUERY_STRING'];
		}
		$ret = Url::create($url);
		$ret->original = $ret->home.$_SERVER['REQUEST_URI'];
		return $ret;
	}

	/**
	 * ���url����ʧ�ܣ��򷵻�false
	 */
	public static function create($url) {
		if(!$url){
			return false;
		}
		$parts = parse_url($url);
		if (empty($parts)) {
			return false;
		}

		$ret=new Url();
		$ret->scheme = isset($parts['scheme']) ? $parts['scheme'] : 'http';
		$ret->host = strtolower($parts['host']);
		$ret->port = isset($parts['port']) ? intval($parts['port']) : 0;
		if(!$ret->port){
			if(isset($ret->defaultPorts[$parts['scheme']])){
				$ret->port = $ret->defaultPorts[$parts['scheme']];
			}else{
				return false;
			}
		}
		$ret->user = isset($parts['user']) ? $parts['user'] : '';
		$ret->pass = isset($parts['pass']) ? $parts['pass'] : '';

		$script = isset($parts['path'])?$parts['path']:'/';
		//·�����ļ�������������ģ���Ҫת��Ϊutf-8֮���ٽ���urlencode����
		if(!preg_match('#^[\x1E-\x7E]+$#is', $script)){
			if(function_exists('is_utf8') && function_exists('mb_convert_encoding') && !is_utf8($script)){
				$script = mb_convert_encoding($script, 'UTF-8', 'GBK,BIG5,ASCII,JIS,UTF-8,EUC-JP,SJIS,SHIFT_JIS');
			}
			if(!function_exists('callback_hzencode')){
				function callback_hzencode($match){
					return '%'.strtoupper(dechex(ord($match[0])));
				}
			}
			$script = preg_replace_callback('#[\x7F-\xFF]#x', 'callback_hzencode', $script);
		}
		$ret->script = $script;

		$path_array = array();
		$arr = explode('/', $script);
		foreach ($arr as $v) {
			if ($v==='..') {
				array_pop( $path_array);
			} elseif ($v!=='.') {
				$path_array[] = $v;
			}
		}

		$ret->file = array_pop($path_array);
		$ret->path = empty($path_array) ? '/' : implode('/',$path_array).'/';
		$ret->query = isset($parts['query']) ? $parts['query'] : '';
		$ret->fragment = isset($parts['fragment']) ? $parts['fragment'] : '';
		$ret->site = $parts['host'] . ($ret->port && !$ret->isDefaultPort() ? ':'.$parts['port'] : '');
		$ret->home =  $ret->scheme . '://' .($ret->user ? trim($ret->user.':'.$ret->pass,':').'@' : '') . $ret->site;
		$ret->uri = $ret->script . ($ret->query ? ('?'.$ret->query) : '');
		$ret->url = $ret->home . $ret->uri;
		return $ret;
	}

	/**
	 * ��ǰ�˿��ǲ��ǵ�ǰЭ���Ĭ�϶˿�
	 */
	public function isDefaultPort(){
		return isset($this->defaultPorts[$this->scheme]) && $this->defaultPorts[$this->scheme]==$this->port;
	}

	/**
	 * ���ݵ�ǰ��ַ�����������ַת��Ϊ����·��
	 * @param string $url
	 * @param boolean $includeDomain �Ƿ����Э�����������
	 * @param boolean $basePath ��׼·��(������/��ʼ,��/��β)
	 */
	public function getFullUrl($url, $includeDomain=true, $basePath=null){
		if(!$url) return '';

		$pre = $includeDomain?$this->home:'';
		switch ($url{0}){
			case '/':
				return (substr($url,1,1)=='/') ? ($this->scheme.':'.$url) : ($pre.$url);
			case '?':
				return $pre.$this->script.$url;
			case '#':
				return $pre.$this->uri.$url;
			default:
				$x=strpos($url,'://');
				if($x>=3 && $x<=6){
					return $url;
				}else{
					if($basePath){
						$ret = $basePath.$url;
					}else{
						$ret = $this->path.$url;
					}
					//���� /./ �� /../ ������ת��Ϊֱ�ӵĵ�ַ
					if(strpos($ret,'./')>0){
						$ret = str_replace('/./', '/', $ret);
						while(preg_match('#(/[^/]+)?/\.\./#', $ret)){
						   $ret = preg_replace('#(/[^/]+)?/\.\./#', '/', $ret, 1);
						}
					}
					return $pre.$ret;
				}
		}
	}

	/**
	 * ��ȡĳ��url�������Ķ�����������
	 */
	public static function getRootDomain($url){
		if(preg_match('#^(?:https?://)?(?:[\w\-\.]+?\.)?([\w\-\.]{3,}\.(?:com|net|org|gov|[a-z]{2})(?:\.[a-z]{2})?)#i', $url, $match)){
			return strtolower($match[1]);
		}
		return $url;
	}
}

/**
 * ���ļ�ʵ�ֵĹ���������Ҫʵ��������
 * ���þ�����
 * $lock = new FileLock('create_cache');
 * if($lock->lock(60,0)){	//����������ʱ60��
 * 	//�ɹ�������
 * 	//�˳���
 * 	$lock->unlock();
 * }else{
 * 	//����̻߳��������ʹ�������
 * }
 * $lock = null;
 */
class FileLock {
	private $file;
	private $handle;
	private $locked=false;
	private $flockIsValid=false;

	/**
	 * ������
	 * @param string $name ������
	 */
	function __construct($name){
		$id = substr(md5($name?$name:'FileLock'),8,16);
		$dir = TEMPDIR.'/'.$id{0}.'/'.substr($id,1,2);
		if(!is_dir($dir)) mkdirs($dir);
		$this->checkFlock();
		$this->file = $dir.'/'.$id.'.~lck';
	}

	function __destruct(){
		$this->unlock();
	}

	/**
	 * ����Ƿ�����ȷ֧��flock������LOCK_NB����
	 * @param boolean
	 */
	private function checkFlock(){
		static $flockIsValid = null;
		if($flockIsValid===null){
			$f = TEMPDIR.'/check.~lck';
			$size = file_exists($f) ? filesize($f) : 0;
			switch($size){
				case 4:
					$flockIsValid=true;
					break;
				case 5:
					$flockIsValid=false;
					break;
				default:
					$flockIsValid=false;
					$handle1=fopen($f, 'w');
					if($handle1!==false){
						if(flock($handle1, LOCK_EX | LOCK_NB)){
							fwrite($handle1, 'false', 5);
							$handle2=fopen($f, 'w');
							if($handle2!==false){
								//if(strstr(PHP_OS,'WIN') && version_compare(PHP_VERSION, '5.2.1', '<')){
								//	//��˵windows��ֻ��php5.2.1֮���֧��LOCK_NB������ִ�е�����϶��Ͳ�֧����
								//}else
								if(flock($handle2, LOCK_EX | LOCK_NB)){
									flock($handle2, LOCK_UN); //ִ�е�����˵����������ʧ��
								}else{
									$flockIsValid=true;
								}
								fclose($handle2);

								if($flockIsValid){
									rewind($handle1);
									ftruncate($handle1, 4);
									fwrite($handle1, 'true');
								}
							}
							flock($handle1, LOCK_UN);
						}
						fclose($handle1);
					}
					break;
			}
		}
		return ($this->flockIsValid = $flockIsValid);
	}

	/**
	 * ����Ƿ��������
	 * @param string $id ��������
	 * @param int $expire ������Ч��
	 * @return boolean
	 */
	public static function canlock($id, $expire){
		$lock = new FileLock($id);
		$ret = $lock->lock($expire,0);
		if($ret) $lock->unlock();
		return $ret;
	}

	/**
	 * ��������
	 * @param int $expire ������Ч�ڣ��룩
	 * @param int $block ����ʱ�䣨�룩���Ϊ0��������
	 * @return boolean
	 */
	function lock($expire=0, $block=0){
		if($this->flockIsValid){
			//���ļ���ռ����Ϊ����־
			$i=0;

			if($expire>0 && file_exists($this->file) && TIME-filemtime($this->file)>$expire){
				@unlink($this->file);
			}

			$this->handle = fopen($this->file, 'w');
			for (; $this->handle===false && $i<$block; $i++) {
				sleep(1);
				$this->handle = fopen($this->file, 'w');
			}
			if($this->handle===false){
				return false;
			}

			$this->locked = flock($this->handle, LOCK_EX | LOCK_NB);
			for (; !$this->locked && $i<$block; $i++) {
				sleep(1);
				$this->locked = flock($this->handle, LOCK_EX | LOCK_NB);
			}
			if(!$this->locked){
				fclose($this->handle);
				$this->handle = 0;
			}
			return $this->locked;
		}else{
			//���ļ��Ƿ������Ϊ����־
			clearstatcache();
			if (file_exists($this->file)) {
				if ($expire>0 && TIME-filemtime($this->file)>$expire){
					@unlink($this->file);
				}elseif($block==0){
					return false;
				}
			}
			$this->handle = fopen($this->file, 'x');
			for ($i=0; $this->handle===false && $i<$block; $i++) {
				sleep(1);
				$this->handle = fopen($this->file, 'x');
			}
			$this->locked = $this->handle!==false;
			return $this->locked;
		}
	}

	/**
	 * ����
	 */
	function unlock(){
		if($this->locked){
			$this->locked = false;
			if($this->flockIsValid){
				flock($this->handle, LOCK_UN);
			}
			fclose($this->handle);
			@unlink($this->file);
		}
	}
}

/*
//�򵥵����ļ��Ƿ������Ϊ��
$handle = fopen(TEMPDIR.'/og.~lck', 'x');
if($handle || filemtime(TEMPDIR.'/og.~lck') < TIME-60){
	//�Ѿ�����
}
if($handle) fclose($handle);
if(file_exists(TEMPDIR.'/og.~lck')) @unlink(TEMPDIR.'/og.~lck');
*/

/**
 * �ļ�ϵͳ����
 */
class CacheFile {
	const DEFAULTEXT = '.~tmp';

	/**
	 * ���㻺���ļ���
	 */
	private static function getLocalFile($name){
		$id = md5($name);
		$dir = TEMPDIR.'/'.$id{0}.'/'.substr($id,1,2).'/';
		return $dir.'/'.$id.self::DEFAULTEXT;
	}

	/**
	 * �жϻ����Ƿ���Ч
	 * @param string $name
	 * @param int $expire ������Ч�ڣ��룩
	 * @return boolean
	 */
	public static function valid($name, $expire=0){
	    $file = self::getLocalFile($name);
	    return file_exists($file) && ($expire<=0 || TIME-filemtime($file)<$expire);
	}
	/**
	 * ��ȡ����
	 * @param string $name
	 * @param int $expire ������Ч�ڣ��룩
	 * @return mixed ����ɹ��ͷ��ػ�������ݣ����ʧ�ܾͷ���false
	 */
	public static function get($name, $expire=0){
		$file = self::getLocalFile($name);
		if(file_exists($file) && ($expire<=0 || TIME-filemtime($file)<$expire)){
			return unserialize(file_get_contents($file));
		}
		return false;
	}
	/**
	 * д�뻺��
	 * @param string $name
	 * @param mixed $value
	 * @return void
	 */
	public static function set($name, $value){
		$file = self::getLocalFile($name);
		$dir = dirname($file);
		if(!is_dir($dir)) {
			mkdirs($dir);
		}
		file_put_contents($file, serialize($value));
	}
}

/**
 * HTTP��Ӧ���ݵı����ļ�����
 * 1. ���û��ָ���������չ�����ļ���Ϊ ����Ŀ¼/16λid.~tmp���ļ��ﻹ���Ᵽ����Щ��Ϣͷ��
 *	�����ʧЧ����ʱ������ڽ��ᱻɾ��
 * 2. ���ָ������չ�����ļ���Ϊ ����Ŀ¼/16λid.��չ�����ļ���û�ж�����Ϣ��ֻ�л������ݣ�
 *	���ʧЧ����ʱ������ڽ��ᱻ���� .~000 ��չ�������´α���ȡʱ�ָ���չ����������
 *	������� .~000 ��չ����һֱû�б���ȡ�������´����ʧЧ����ʱ���ᱻɾ��
 */
class CacheHttp {
	private $localFile;
	private $hitCount; //����
	private $headerLength;
	private $handle = null;
	private $lock = null;
	private $forWrite = false;
	private $writeHeader = true;
	public $contentLength;
	public $headers = array();
	public $shouldUpdate = false;
	public $mtime = 0; 					//�����ļ��޸�ʱ�䣬Ҳ�����ڴ���ʱ��֤���ڴ���ʱ�䣬�����޷����ͻ����״η���ʱ����
	public $cacheext = null;
	const TEMPTAIL = '._temp_';			//��ʱ�����ļ��Ľ�β����
	const DEFAULTEXPIREOFTEMP = 3600; 	//��ʱ��������Ч��
	const DEFAULTEXT = '.~tmp';			//Ĭ�ϵĻ�����չ��
	const PENDINGEXT = '.~000';			//��������չ�����������ϱߵ�DEFAULTEXT������ͬ

	/**
	 * ����HTTPͷ�ж��Ƿ�Ӧ�ñ�����
	 * @param array $headers HTTP��Ӧͷ���飨��ֵ����Сд��
	 * @param bool $pageandjs ��ҳ��js��������ҳ���¼�������б仯���������Դ�ļ��Ļ�����Ʋ�ͬ
	 * @param bool $havecookie �Ƿ���cookie
	 * @return bool ������Ա�����ͷ��ؼƻ�������������ҳ��js���1Сʱ���������1�죩������ͷ���false
	 */
	public static function shouldCache($headers, $pageandjs, $havecookie){
	    $date = isset($headers['date'])?intval(strtotime($headers['date'])):0;
		$localtime = TIME;
		$maxSeconds = $pageandjs ? 3600 : 86400;
        $shortSeconds = 900;

		if(isset($headers['pragma']) && strpos($headers['pragma'],'no-cache')!==false) {
		    //��ֹ�˻���
			return false;
		}
		if(isset($headers['cache-control'])) {
			$cacheControl = $headers['cache-control'];
			if(preg_match('#no-(?:cache|store)#',$cacheControl)){
			    //��ֹ�˻���
				return false;
			}elseif($pageandjs && $havecookie && strpos($cacheControl,'public')===false){
                //������cookie����ҳ�������ж�
			}elseif(preg_match('#max-age=(\d+)#',$cacheControl,$match)){
                $seconds = intval($match[1]);
                if($seconds>10){
                    return min($seconds,$maxSeconds);
                }else{
                    //���ڻ�������С��10��ģ������ж�
                }
			}
		}
		if(isset($headers['expires'])){
		    $expires = $headers['expires']=='-1'?0:strtotime($headers['expires']);
		    if($date && $expires<=$date){
		        //����ʱ���Ѿ����ڷ�������ǰʱ�䣬��Ӧ��������
		        return false;
		    }elseif(!$date && $expires-$localtime<600) {
	            //����ʱ��10����֮�ڼ������ڣ����ǵ��������ͻ���֮����ܴ��ڵ�ʱ�����԰��������������Ϊ���ʺϱ�����
	            return false;
	        }else{
	            //Ӧ�ñ�����
	            return min($expires-($date?$date:$localtime), $maxSeconds);
	        }
		}
		if(isset($headers['last-modified'])){
			$lastModified = $headers['last-modified']=='-1'?0:strtotime($headers['last-modified']);
			if($date && $lastModified>=$date) {
			    //�޸�ʱ�䲻���ڷ�����ʱ�䣬��Ӧ������
			    return false;
			}elseif(!$date && $lastModified>$localtime-600){
			    //�޸�ʱ��ȱ���ʱ��û����10���ӣ����ǵ��������ͻ���֮����ܴ��ڵ�ʱ�����԰��������������Ϊ���ʺϱ�����
			    return false;
			}else{
				//Ӧ�ñ�����
				return min(($date?$date:$localtime)-$lastModified, $maxSeconds);
			}
		}

		$etag = isset($headers['etag']) ? trim($headers['etag'],'" \'') : '';
		$contentDisposition = isset($headers['content-disposition']) ? $headers['content-disposition'] : '';
		if(!$pageandjs && ($etag || strpos($contentDisposition, 'attachment')!==false)){
		    //������Դ�ļ����������etag���������ظ���������Ϊ��Ҫ����
		    return $maxSeconds;
		}

        $isajax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH']=='XMLHttpRequest';
        if(!$isajax && !$havecookie){
            //���û�н�ֹ���棬Ҳ����ajax��Ҳû��cookie����ǿ�ƻ���15����
            return $shortSeconds;
        }

		//ִ�е��ˣ����������ж�Ϊ������δ�����ܱ�����
		return false;
	}

	/**
	 * ����������Ϣ�ͷ������������ETag��Last-Modified��ֵ���жϻ����Ƿ���Ҫ���µ��ͻ���ȥ
	 * ���ͻ����������etag��������ϵ�etag�Ƿ���ͬ,
	 * ��Ҫ��.htaccess�����������¼��е����ã����Ժϲ�����$_SERVER��߲��ܼ�������ֵ
	 * RewriteRule .* - [E=HTTP_IF_NONE_MATCH:%{HTTP:If-None-Match}]
	 * RewriteRule .* - [E=HTTP_IF_MATCH:%{HTTP:If-Match}]
	 * RewriteRule .* - [E=HTTP_IF_MODIFIED_SINCE:%{HTTP:If-Modified-Since}]
	 * @param string $cachedEtag   �������etagֵ
	 * @return boolean true��ʾ��Ҫ���´���
	 */
	public static function isModified($headers){
		$cachedEtag=isset($headers['etag'])?trim($headers['etag'],'" \''):null;
		$cachedModifiedTime=isset($headers['last-modified'])?strtotime($headers['last-modified']):null;
		if($cachedEtag){
			if(isset($_SERVER['HTTP_IF_NONE_MATCH']) && ($clientEtag=$_SERVER['HTTP_IF_NONE_MATCH'])) {
				return !self::matchEtag($cachedEtag, $clientEtag);
			}
			if(isset($_SERVER['HTTP_IF_MATCH']) && ($clientEtag=$_SERVER['HTTP_IF_MATCH'])) {
				return self::matchEtag($cachedEtag, $clientEtag);
			}
		}
		if($cachedModifiedTime){
			if(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && ($clientModifiedTime=$_SERVER['HTTP_IF_MODIFIED_SINCE'])) {
				return (strtotime($clientModifiedTime)!=$cachedModifiedTime);
			}
		}
		return true;
	}

	/**
	 * �������etagֵ�Ƿ�ƥ��
	 * @param string $serverEtag
	 * @param string $requestEtag ����ͷ���IF_NONE_MATCHֵ�������Ƕ��
	 * @return bool
	 */
	public static function matchEtag($serverEtag, $requestEtag){
		$serverEtag = trim(str_replace('W/', '', $serverEtag),' "');
		$requestEtag = str_replace(array('W/','"'), ' ', $requestEtag);
		return strpos(" {$requestEtag} "," {$serverEtag} ")!==false;
	}

	/**
	 * ����ETag
	 * @param mixed $content
	 */
	public static function makeEtag($content){
		$s = serialize($content);
		return '"'.substr(sha1($s),0,4).'-'.substr(md5($s),8,16).'"';
	}

	function __destruct(){
		$this->close();
	}

	/**
	 * �رջ���
	 */
	public function close(){
		if(is_resource($this->handle)){
			fclose($this->handle);
			$this->handle = null;
			if($this->forWrite==true) unlink($this->localFile);
			if($this->lock) $this->lock->unlock();
		}
	}

	/**
	 * ���㻺���ID
	 * @param string $url Ҫ������ļ�������url
	 * @param string $salt ���������Ķ�������
	 * @return string �����ID
	 */
	public static function getCacheID($url, $salt){
		return substr(md5($url.($salt?"\r{$salt}":'')),8,16);
	}

	/**
	 * ���㻺�汾��·��
	 * @param string $cacheDir �����ļ��У���Ҫ�Լ���֤�Ѿ�������
	 * @param string $url Ҫ������ļ�������url
	 * @param string $salt ���������Ķ�������
	 * @param bool $isTemp ��ʱ�Ļ����ļ�(��ʱ��������ɺ�Ḵ�Ƶ������Ļ����ļ�)
	 * @param string $ext �����ļ�����չ��
	 * @return string �����ļ�������·��
	 */
	private static function getFile($cacheDir, $url, $salt, $isTemp, $ext=self::DEFAULTEXT){
		$id=self::getCacheID($url, $salt);
		return $cacheDir.'/'.$id{0}.'/'.substr($id,1,2).'/'.$id.($ext?$ext:self::DEFAULTEXT).($isTemp?self::TEMPTAIL:'');
	}

	/**
	 * ��ȡ����
	 * @param int $size ÿ�ζ�ȡ���ֽ���
	 * @return string ��������ȡ�Ļ��棬����ļ��Ѿ������򷵻�false
	 */
	public function read($size=HTTP_BUFFERING){
		$ret=fread($this->handle,$size);
		if(!isset($ret{0}) && $this->eof($this->handle)){
			return false;
		}else{
			return $ret;
		}
	}

	/**
	 * �ӵ�ǰλ������ƶ�ָ��
	 * @param int $offset ����ƶ����ֽ���
	 */
	public function seek($offset){
		return fseek($this->handle,$offset,SEEK_CUR);
	}

	/**
	 * ��ȡ�����Ƿ����ļ���β
	 * @return bool
	 */
	public function eof(){
		return feof($this->handle);
	}

	/**
	 * ��ȡ����
	 * @param string $cacheDir ���汣��λ��
	 * @param string $url ����������url
	 * @param string $salt=null ���������Ķ������ԣ�����ʹ���д����ԵĻ��棬����������ʹ���޴����ԵĻ��棩
	 * @param string $ext �����ļ�����չ��
	 * @param int $forceExpire ǿ�ƻ�����Ч��(��)��0��ʾʹ��Ĭ�ϵĻ�����Ч����
	 * @return mixed ����ɹ��ͷ��ػ���������ļ�ָ��ָ�����ݿ�ʼ�������ʧ�ܾͷ���false
	 */
	public static function get($cacheDir, $url, $salt=null, $ext=self::DEFAULTEXT, $forceExpire=0){
		$shouldUpdate = false;
		if(!$ext) $ext=self::DEFAULTEXT;

		$localFile = null;
		$cacheFile = self::getFile($cacheDir, $url, $salt, false, $ext);
		if(file_exists($cacheFile)) {
			$localFile = $cacheFile;
		}else{
			if($ext!=self::DEFAULTEXT){
				//��Դ�ļ������Ƿ���ڴ������ļ�
				$s=$cacheFile.self::PENDINGEXT;
				if(file_exists($s)){
					if(rename($s,$cacheFile)){
						$localFile = $cacheFile;
						$shouldUpdate = true;
					}else{
						return false;
					}
				}
				if(!$localFile){
					//��Դ�ļ������Ƿ��������ͨ������
					$s=substr_replace($cacheFile,self::DEFAULTEXT,-strlen($ext));
					if(file_exists($s)) $localFile = $s;
				}
			}
			if(!$localFile && $salt){
				//�����Ƿ��������޹���
				$s=self::getFile($cacheDir, $url, null, false, $ext);
				if(file_exists($s)) $localFile=$s;
			}
		}
		if(!$localFile) return false;

		$handle=@fopen($localFile, 'rb');
		if($handle!==false){
			$cache = new CacheHttp;
			$cache->handle = $handle;
			$cache->localFile = $localFile;
			$cache->mtime = filemtime($localFile);
			$cache->cacheext = fileext($localFile);
			if($forceExpire>0 && TIME-$cache->mtime>$forceExpire){
				//ǿ�ƹ���
				$cache->close();
				return false;
			}

			if($cache->cacheext==self::DEFAULTEXT){
				$cache->hitCount = base_convert(fread($handle,5),36,10);
				$cache->headerLength = base_convert(fread($handle,5),36,10);
				$cache->contentLength = base_convert(fread($handle,10),36,10);
				if($cache->contentLength<=0){
					$cache->close();
					return false;
				}
				$cache->headers = unserialize(fread($handle,$cache->headerLength));
				if($cache->headers['__url']!==$url){
					//���¼�黺���������url���Ա��⻺��id�㷨��ײ��ɵ�����
					$cache->close();
					return false;
				}
				$cache->headers['etag'] = isset($cache->headers['etag']) ? $cache->headers['etag'] : md5_file($localFile);
				$cache->headers['__ext'] = fileext($url); //Զ���ļ���չ��
				if(isset($cache->headers['__expire'])){
					$cache->shouldUpdate=$cache->headers['__expire']<TIME-$cache->mtime;
				}
			}else{
				$cache->hitCount = 1;
				$cache->headerLength = 0;
				$cache->contentLength = filesize($localFile);
				$cache->headers = array(
					'cache-control'=>'public, max-age=86400',
					'last-modified'=>gmdate('D, d M Y H:i:s \G\M\T', $cache->mtime),
					'expires'=>gmdate('D, d M Y H:i:s \G\M\T', $cache->mtime+86400),
					'__ext'=>$cache->cacheext, //Զ���ļ���չ��
				);
				if(TIME-$cache->mtime<600) $shouldUpdate=false; //10�����ڲ���Ҫ�ظ�����
				$cache->shouldUpdate=$shouldUpdate;
			}

			//������ڣ�����Ƿ���Ҫ����
			if($cache->shouldUpdate && FileLock::canlock($cache->localFile.self::TEMPTAIL, self::DEFAULTEXPIREOFTEMP)){
				//��ʱ�����ܹ���������˵���˻��治�����ڸ��£�����shouldUpdate=true֪ͨ�����߿��Ը����ˣ�����ͼ���ʹ���Ѿ������˵Ļ���
				$cache->shouldUpdate = true;
				return $cache;
			}
			return $cache;
		}else{
			return false;
		}
	}

	/**
	 * ������ʱ������󣬲�д��ͷ����Ϣ�����û��ʹ��append����д��������ݣ�ҳ�����ʱ��ʱ���潫�ᱻ�Զ�ɾ��
	 * @param string $cacheDir ���汣��λ��
	 * @param string $url ����������url
	 * @param array $header �������HTTPͷ
	 * @param string $salt ���������Ķ������ԣ���ҪΪͬһ��url����������user-agent�Ȳ�ͬ������治ͬ�Ļ���ʱ���ã�
	 * @param string $expire ������Ч�ڣ��룩��Ĭ��3600�루1Сʱ��
	 * @param string $ext �����ļ�����չ��
	 * @return mixed ����ɹ��ͷ�����ʱ����������ʧ�ܾͷ���false
	 */
	public static function create($cacheDir, $url, $header, $salt=null, $expire=3600, $ext=self::DEFAULTEXT){
		if(!$ext) $ext=self::DEFAULTEXT;
		$localFile = self::getFile($cacheDir, $url, $salt, true, $ext);
		$lock = new FileLock($localFile);
		if(!$lock->lock(self::DEFAULTEXPIREOFTEMP, 0)){
			return false;
		}

		if(file_exists($localFile)){
			unlink($localFile);
		}else{
			$dir = dirname($localFile);
			if(!is_dir($dir)) {
				if(!mkdirs($dir)){
					$lock->unlock();
					return false;
				}
			}
		}

		$handle = fopen($localFile, 'xb');
		if($handle===false){
			$lock->unlock();
			return false;
		}

		$header['__url'] = $url;
		$header['__expire'] = intval($expire);
		$headerStr = serialize($header);

		$cache = new CacheHttp;
		$cache->forWrite = true;
		$cache->localFile = $localFile;
		$cache->handle = $handle;
		$cache->lock = $lock;
		if($ext==self::DEFAULTEXT){
			$cache->writeHeader=true;
			$cache->hitCount = 0;
			$cache->headerLength = strlen($headerStr);
			$cache->contentLength = 0;
			fwrite($handle, str_pad(base_convert($cache->hitCount,10,36), 5));
			fwrite($handle, str_pad(base_convert($cache->headerLength,10,36), 5));
			fwrite($handle, str_pad(base_convert($cache->contentLength,10,36), 10));
			fwrite($handle, $headerStr, $cache->headerLength);
		}else{
			$cache->mtime=TIME;
			$cache->writeHeader=false;
		}
		return $cache;
	}

	/**
	 * ׷�ӻ����HTTP��Ӧ���ݵ����� (�����Ҫ����finish�������д��)
	 * @param string $data
	 */
	public function write($data){
		$len = strlen(strval($data));
		if($len===0) return;
		if(false !== fwrite($this->handle, $data)){
			$this->contentLength += $len;
		}
	}

	/**
	 * �����»����ļ����޸�����
	 */
	public function touch(){
		$ret = is_file($this->localFile) && touch($this->localFile);
		if($ret && $this->cacheext!=self::DEFAULTEXT){
			$t=TIME;
			$this->headers['last-modified']=gmdate('D, d M Y H:i:s \G\M\T', $t);
			$this->headers['expires']=gmdate('D, d M Y H:i:s \G\M\T', $t+86400);
			$shouldUpdate=false;
		}
		return $ret;
	}

	/**
	 * �����HTTP��Ӧ���ݵı��棬ֻ�д�ʱ�Ż����ʱ����ת���������Ļ���
	 * ����ɹ����ͷ��ػ����ļ�����������
	 */
	public function finish(){
		$ret = null;
		if($this->contentLength>0){
			if($this->writeHeader){
				fseek($this->handle, 5+5, SEEK_SET);
				fwrite($this->handle, str_pad(base_convert($this->contentLength,10,36), 10));
			}
			$new = substr($this->localFile, 0, 0-strlen(self::TEMPTAIL));

			//��ô��ֹ��д��ͻ�أ�Խ��Ͷ�ȡԽƵ�����ļ�Ӱ��Խ��
			fclose($this->handle);
			if(!rename($this->localFile, $new)){
				copy($this->localFile, $new);
				@unlink($this->localFile);
			}
			$ret = $new;

			//�����޸�ʱ��ΪΪ���洴��ʱ��
			$now_mtime=filemtime($new);
			if($this->mtime && $now_mtime && $this->mtime!==$now_mtime){
				if(!touch($new, $this->mtime)){
					touch($new);
				}
			}
		}else{
			fclose($this->handle);
			@unlink($this->localFile);
		}
		$this->localFile = null;
		if($this->lock) $this->lock->unlock();
		return $ret;
	}

	/**
	 * ���ָ��Ŀ¼�µĹ�����ʱ�ļ�
	 * ÿ����1��·��������ÿ��5�룬����ÿɾ��50���ļ���������һ������M��
	 * @param string $dir
	 * @param int $checkTime �������Ч���ʱ��
	 * @param resource $fileHandle
	 * @return boolean
	 */
	private static function clearMatchFile($dir, &$progress){
		$basedirLen=strlen($progress['basedir'])+1;
		$defaultExtPos=-strlen(self::DEFAULTEXT);
		$checktime=$progress['checktime'];

		$files = scandir($dir);
		if($files===false) return false;

		foreach ($files as $_f){
			if($_f=='.' || $_f=='..'){
				continue;
			}

			//�����Ѿ��������ļ�
			$_full = $dir.'/'.$_f;
			if ($progress['lastpos'] && strcmp(substr($_full,$basedirLen),$progress['lastpos'])<0) {
				continue;
			}

			$time = time();

			//ִֻ��ָ��ʱ��
			if($time>$progress['endtime']){
				$progress['lock']->unlock();
				fclose($progress['filehandle']);
				exit;
			}

			//�����M��
			if($progress['changeddir']>1 || $time-$progress['progresstime']>=5 || $progress['changedfile']>50){
				$progress['changeddir']=0;
				$progress['changedfile']=0;
				$progress['progresstime']=$time;
				rewind($progress['filehandle']);
				fwrite($progress['filehandle'], str_pad(substr($_full,$basedirLen),10,' '));
			}

			if(is_dir($_full)){
				//��Ŀ¼
				self::clearMatchFile($_full, $progress);
				$progress['changeddir']++;
			}else{
				$shouldDel=$shouldPending=false;
				if(!$checktime){
					$shouldDel=true;
				}else{
					$ext=substr($_f,$defaultExtPos);
					if($ext==self::DEFAULTEXT){
						//��ͨ���棨1��û�б�ʹ�þ�ɾ����
						$shouldDel=(filemtime($_full)<$checktime && fileatime($_full)<$checktime);
					}elseif($ext==self::PENDINGEXT){
						//���ڱ�����Ļ��棨�ڽ���֮ǰ������ļ����ᱻɾ����
						$shouldDel=date('d',fileatime($_full))!=TODAY;
					}elseif($ext{1}=='~'){
						//������չ����~��ͷ�Ļ����ļ������� .~lck .~cok
						$shouldDel=filemtime($_full)<$checktime;
					}else{
						//��ʵ��չ���Ļ��棨1��û�б��޸ľ͹��𣬹��𱻻ָ�ʱ������ļ��޸�ʱ�䣩
						$shouldPending=filemtime($_full)<$checktime;
					}
				}
				if($shouldDel){
					$progress['changedfile']++;
					$success = unlink($_full);
					if(defined('DISPLAY_CLEARCACHE_LOG')) echo $success ? "." : ' fail ';
				}elseif($shouldPending){
					$progress['changedfile']++;
					$mtime=filemtime($_full);
					if(!rename($_full, $_full.self::PENDINGEXT)){
						$success = unlink($_full);
						if(defined('DISPLAY_CLEARCACHE_LOG')) echo $success ? "." : ' fail ';
					}else{
						//��ֹ��������ļ��ڱ��ֱ�ɾ��
						if(!touch($_full.self::PENDINGEXT, $mtime, $progress['starttime'])){
							touch($_full.self::PENDINGEXT);
						}
					}
				}
			}
		}
	}

	/**
	 * ÿ�����1����ڣ�����ָ��ʱ��û�б�ʹ�ã��Ļ����ļ�
	 * ���û�е�ǰ�����ļ����Ϳ�ʼ����
	 * �����ǰ�����ļ���Ϊ�գ��ʹӵ�ǰ�����ļ�������¼�ĵ�ǰλ�ÿ�ʼ��������
	 * ������������ļ�Ϊ�գ�˵���Ѿ�����һ���ˣ���������
	 * @param string $subdir ���Ϊnull���Ǽ����������Ŀ¼������ֻ���ĳ��������Ŀ¼
	 * @param int $expireDay ������ʱ���Ǽ���֮ǰ�Ļ����ļ�����ΪĬ����չ�����ᱻɾ������Ϊ��ʵ��չ�������޸�Ϊ��������չ������Ϊ��������չ�����ᱻɾ���������ֵΪ0��ɾ�����л����ļ�
	 * @return ɾ�����֮�󷵻�true
	 */
	public static function clearOverdueCache($subdir=null, $expireDay=1){
	    $dir = (is_string($subdir) && strlen($subdir)>0) ? (TEMPDIR.'/'.$subdir) : TEMPDIR;
		$day = intval(TIME / 86400);
		$checkFile = "{$dir}/day_{$day}.~tmp";

		if(!file_exists($checkFile)){
			$f="{$dir}/day_".($day-1).".~tmp";
			if(file_exists($f)) unlink($f);
			$written = file_put_contents($checkFile, str_pad('0',10,' '));
            if(!$written){
                if(function_exists('error_get_last')){
                    $e = error_get_last();
                    $errmsg = $e['message'];
                    if(strpos($errmsg,'possibly out of free disk space')!==false || strpos($errmsg,'No space left on device in')!==false){
                        //���̿ռ����ˣ������Ŀ¼�µ����л���
                        clear_temp_dir();
                    }
                }
				exit;
			}
		}elseif(filesize($checkFile)===0){
			if(defined('DISPLAY_CLEARCACHE_LOG')) echo $dir.' ��Ĺ��ڻ������������һ����';
			return true;
		}

		//��ֹ����(ÿ��������ƻ���13���ڽ���)
		$lock = new FileLock('clearOverdueCache');
		if($lock->lock(15, 0)){
			$handle=fopen($checkFile, 'r+');
			if($handle!==false){
				//��ɾ���ļ��Ĺ����к����û��жϺͳ�ʱ
				@ignore_user_abort(true);
				$progress = array(
					'basedir' => $dir,
					'lastpos' => trim(fread($handle, 10)),
					'filehandle' => $handle,
					'starttime' => TIME,
					'endtime' => TIME+13,
					'checktime' => intval($expireDay)<=0 ? null : (TIME-$expireDay*86400),
					'progresstime' => 0,
					'changeddir' => 0,
					'changedfile' => 0,
					'lock' => $lock,
				);
				self::clearMatchFile($dir, $progress);
				//��Ŀ¼�Ļ���������֮��Ż�ִ�е�����
				ftruncate($handle, 0);
				fclose($handle);
				$lock->unlock();
				if(defined('DISPLAY_CLEARCACHE_LOG')) echo $dir.' ��Ĺ��ڻ������������';
			}
			$lock->unlock();
			return true;
		}else{
			if(defined('DISPLAY_CLEARCACHE_LOG')) echo '������������ִ�������������';
		}
		return false;
	}

	/**
	 * �Ƿ�Ӧ������˻�����Ŀ¼
	 * @param string $subdir ���Ϊnull���Ǽ����������Ŀ¼������ֻ���ĳ��������Ŀ¼
	 */
	public static function canClearOverdueCache($subdir=null){
	    $dir = (is_string($subdir) && strlen($subdir)>0) ? (TEMPDIR.'/'.$subdir) : TEMPDIR;
		$day=intval(TIME / 86400);
		$checkFile="{$dir}/day_{$day}.~tmp";
		if(!file_exists($checkFile)) return is_dir($dir) ? true : false;
		if(filesize($checkFile)===0) return false;
		return true;
	}
}


/**
 * ʹ�� pfsockopen �� fsockopen ʵ��httpЭ��
 */
class HttpFsockopen extends Http {
	public $version=null;
	private $socket=null;
	private $keepalive=false;
	private $remoteIp=null;
	private $chunked=false;
	private $contentEncoding=null;
	private $newLocation=null;
	private $leftRedirectCount=self::MAX_REDIRECTS;

	protected function onCreate() {
		$this->socket = null;
		$this->keepalive = $this->version=='pfsockopen';
	}

	protected function onDestroy($force=false) {
		if(!PERSISTENT_CONNECTION || $force || !$this->keepalive){
			$this->disconnect();
		}else{
			$this->socket=null;
		}
	}

	/**
	 * ����Զ�̷�����
	 */
	private function connect(){
		$err_no=0;
		$err_str=null;
		$func_fsockopen=$this->version;
		if($this->proxy && $this->remoteIp!='127.0.0.1'){
			list($ip,$port)=explode(':',$this->proxy);
			$hostname='tcp://'.$ip;
		}else{
			$hostname=($this->url->scheme === 'https' && $this->config['enable_ssl'] ? 'ssl://' : 'tcp://') . $this->remoteIp;
			$port=$this->url->port;
		}
		try {
			if($func_fsockopen=='stream_socket_client'){
				$this->socket=$func_fsockopen($hostname.':'.$port, $err_no, $err_str, $this->connectTimeout);
				//flag����: STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT
			}else{
				$this->socket=$func_fsockopen($hostname, $port, $err_no, $err_str, $this->connectTimeout);
			}
		} catch (Exception $e) {
			return false;
		}

		if($this->socket){
			stream_set_blocking($this->socket, true);
			return true;
		}else{
			$this->lastError="internet";
			return false;
		}
	}

	private function disconnect(){
		if (is_resource($this->socket)) {
			fclose($this->socket);
			$this->socket=null;
		}
	}

	private function eof(){
		return is_resource($this->socket) && feof($this->socket);
	}

	private function active(){
		if(is_resource($this->socket)){
			$status=stream_get_meta_data($this->socket);
			return !$status['timed_out'];
		}else{
			return false;
		}
	}

	protected function prepareRequqestHeaders($includeMethodAndHost, $returnType){
		if($this->version=='pfsockopen'){
			$this->requestVersion='1.1';
			$this->setRequestHeader('connection', 'keep-alive');
		}
		return parent::prepareRequqestHeaders($includeMethodAndHost, $returnType);
	}

	/**
	 * ������Ӧͷ
	 * @return bool
	 */
	private function receiveResponseHeaders(){
		$headerText='';
		while(!$this->shouldStop && $this->active() && !$this->eof()){
			//���ýű���ʱ
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);

			$line=fgets($this->socket, 1024);
			if($line===false){
				//ʧ��
				return false;
			}elseif(!$this->responseStatusCode){
				//�ϴε�����û�з�����ϣ�����������
				$this->parseResponseStatus($line);
			}elseif(trim($line)==''){
				//����ǿ���˵����Ӧͷ����
				break;
			}else{
				//��Ӧͷ
				$headerText.=$line;
			}
		}
		if($this->shouldStop || !$this->responseStatusCode) return false;
		$this->parseResponseHeaders($headerText);

		if($this->redirect && $this->requestMethod!='HEAD' && in_array($this->responseStatusCode,array(301,302)) && $this->leftRedirectCount>0 && !empty($this->responseHeaders['location']) && empty($this->responseHeaders['set-cookie'])){
			//�����ض������û��set-cookie�������ڷ�����������ض��򣬵������ƴ���
			$this->newLocation=$this->responseHeaders['location'];
			$this->leftRedirectCount--;
		}else{
			$this->contentLength = (int)$this->getResponseHeader('content-length', -1);
			$this->chunked = strtolower($this->getResponseHeader('transfer-encoding'))=='chunked';
			$this->contentEncoding = strtolower($this->getResponseHeader('content-encoding'));
		}
		return $this->responseStatusCode>0;
	}

	/**
	 * ��������
	 * @return bool �Ƿ�ɹ���ȡ��ȫ��������
	 */
	private function receiveResponseBody(){
		$allContent='';
		$finished=false;
		$haveRead=0;
		$toread=0;
		while(!$this->shouldStop && !connection_aborted() && $this->active() && !$this->eof()){
			if($this->chunked && $toread>0){
				//����
			}elseif($this->chunked){
				$line=@fgets($this->socket);
				if(trim($line)=='') $line=@fgets($this->socket);
				if(!$this->active()) return false;
				if($line===false){
					return false;
				}else{
					$toread = hexdec(trim($line));
					if($toread===0) {
						$finished=true;
						break;
					}
				}
			}elseif($this->contentLength>-1){
				$toread = $this->contentLength-$haveRead;
				if($toread<=0){
					$finished=true;
					break;
				}elseif($toread>HTTP_BUFFERING){
					$toread=HTTP_BUFFERING;
				}
			}else{
				if(feof($this->socket)){
					$finished=true;
					break;
				}else{
					$toread=HTTP_BUFFERING;
				}
			}

			$data = fread($this->socket, $toread);

			if($data!==false){
				$toread -= strlen($data);
				$haveRead += strlen($data);
				if($this->shouldUnzip){
					$allContent.=$data;
				}else{
					$this->onReceivedBody($data, false, false);
				}
				if($this->contentLength>-1 && $haveRead>=$this->contentLength){
					$finished=true;
					break;
				}
			}else{
				return false;
			}

			//���ýű���ʱ
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		}

		if($this->eof()) $finished=true;

		if(!$this->shouldStop && !connection_aborted() && $finished){
			if(!PERSISTENT_CONNECTION || !$this->keepalive || strtolower($this->getResponseHeader('connection'))=='close' || $this->eof()){
				$this->disconnect();
			}else{
				$this->socket=null;
			}

			if($this->shouldUnzip){
				//��ѹ����������Ҫ�����ʱ�Ƚ��н�ѹ��û���ʱ���ܷ��ظ�������
				$allContent=$this->unzip($allContent, $this->responseHeaders['content-encoding']);
				$this->onReceivedBody($allContent, true, false);
			}else{
				$this->onReceivedBody('', true, false);
			}
			return true;
		}else{
			$this->lastError='timeout';
			$this->disconnect();
			return false;
		}
	}

	protected function doRequest(){
		$this->socket=null;
		$this->keepalive=false;
		$this->remoteIp=null;
		$this->chunked=false;
		$this->contentEncoding=null;
		$this->newLocation=null;
		$this->leftRedirectCount=self::MAX_REDIRECTS;

		$lastHost=null;
		$retry_count = 0;
		$this->addHttpLog("\n>>> version��{$this->version}\n");
		do {
			$retry = false;
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);

			$this->lastUrl = $this->url->url;
			if($lastHost!=$this->url->host){
				$lastHost=$this->url->host;
				$this->remoteIp=$this->resolve($lastHost);
				$this->addHttpLog("\n>>> ����������{$lastHost} => {$this->remoteIp}\n");
			}
			$requestHeader=$this->prepareRequqestHeaders(true, 'string');
			$postData=$this->requestMethod=='POST' ? $this->postData : null;
			//== ����Զ�̷����� ==
			if(!$this->socket && !$this->connect()){
				if($retry_count===1){
					//�����һ������ʧ�ܣ���ǿ�ƽ���һ������
					$this->remoteIp=$this->resolve($this->url->host, true);
					$this->addHttpLog("\n>>> ����������{$this->url->host} => {$this->remoteIp}\n");
				}
				$retry=true;
				$retry_count++;
				continue;
			}
			$this->addHttpLog("\n>>> ���ӷ�������".($this->socket ? '�ɹ�' : 'ʧ��')."\n");
			if($this->shouldStop) return false;
			//== ����HTTP���� ==
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);
			$this->addHttpLog("\n>>> ����\n{$requestHeader}");
			$writen = fwrite($this->socket, $requestHeader, strlen($requestHeader));
			if(!$writen){
				$this->lastError='timeout';
				$this->disconnect();
				$retry=true;
				$retry_count++;
				continue;
			}
			if($this->shouldStop) {
				$this->disconnect();
				return false;
			}
			//== �ύpost���� ==
			if($this->requestMethod=='POST' && strlen($postData)>0){
			    $this->addHttpLog("\n{$postData}\n\n");
				$writen = fwrite($this->socket, $postData, strlen($postData));
				if(!$writen){
					$this->lastError='timeout';
					$this->disconnect();
					$retry=true;
					$retry_count++;
					continue;
				}
			}
			if($this->shouldStop) {
				$this->disconnect();
				return false;
			}
			//== ���ýű���ʱ��socket��ȡ��ʱ ==
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
			stream_set_timeout($this->socket, $this->readTimeout); //���ĳһ��fgets��fread�ĳ�ʱ
			//== ����HTTPͷ ==
			if(!$this->receiveResponseHeaders()){
				$this->lastError='timeout';
				$this->disconnect();
				$retry=true;
				$retry_count++;
				continue;
			}

			if($this->logFileHandle){
				$this->addHttpLog("\n<<<\n");
				$this->addHttpLog($this->responseHeadersText);
				$this->addHttpLog("\n\n");
			}

			if($this->shouldStop) {
				$this->disconnect();
				return false;
			}
			//== ������������ض���
			if($this->newLocation){
				if($lastHost!=$this->url->host || !$this->keepalive){
					$this->disconnect();
				}
				$retry=true;
				if($this->leftRedirectCount<=0){break;}
				$this->requestMethod='GET';
				$this->responseStatusCode=0;
				$url = $this->url->getFullUrl($this->newLocation,true);
				$this->url = Url::create($url);
				$this->newLocation=null;
				if(!$this->url) {$this->lastError=400; break;}
				continue;
			}
			//== �ɹ����յ�HTTPͷ
			$this->lastError=null;
		} while ( $retry && $retry_count<$this->maxRetry );

		//�Ƿ�ɹ��յ�HTTPͷ
		if($this->lastError){
			$this->disconnect();
			return false;
		}

		//֪ͨ�������յ�HTTPͷ
		$this->onReceivedHeader($this->responseHeaders, false);
		if($this->shouldStop || $this->lastError){
			$this->disconnect();
			return false;
		}

		//�κβ�������Ϣ�����Ϣ����1XX��204��304��50X����Ӧ��Ϣ���κ�ͷ(HEAD���ײ�)�������Ӧ��Ϣ����������һ�����У�CLRF��������
		if($this->requestMethod=='HEAD' || in_array($this->responseStatusCode, array(100,101,204,301,302,304))){
			$this->disconnect();
			$this->onReceivedBody(null, true, false);
			return true;
		}

		//������Ӧ��
		return $this->receiveResponseBody();
	}
}

/**
 * ʹ�� cUrl ģ��ʵ��httpЭ��
 * �п��ܷ������뷵�صľ���206��Ϣ�����Ե����յ�һ��������ʱ���������ظ������ˣ��ⲿ�ִ�����ʱ���õ�
 */
class HttpCurl extends Http {
	private $headers=null; //����ȡhead�Ĺ�������ʱ����head��Ϣ���ڽ��ղ��������֮��������
	private $keepAlive=false;
	private $allData=null;
	private $receivedLength=0;
	private $allContentLength=0;
	private $startTime=0;
	private $curlHandle=0;
	private $newLocation=null;
	private $leftRedirectCount=self::MAX_REDIRECTS;

	protected function onCreate() {
		$this->keepAlive = false;
	}

	protected function onDestroy($force=false) {

	}

	protected function prepareRequqestHeaders($includeMethodAndHost, $returnType){
		$this->requestVersion=1.1; //$this->keepAlive?'1.1':'1.0';
		//$this->setRequestHeader('connection', $this->keepAlive?'keep-alive':'close');
		return parent::prepareRequqestHeaders($includeMethodAndHost, $returnType);
	}

	/**
	 * ��֤cur��ִ��ʱ�仹ʣ��һ�ζ�ȡ��ʱʱ��
	 */
	private function preserveTimeout(){
		if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		$sec = ceil(microtime(true)-$this->startTime) + $this->readTimeout;
		curl_setopt($this->curlHandle, CURLOPT_TIMEOUT, $sec);
	}

	/**
	 * ��ȫ��HTTP�������ʱ,����false��ֹͣ��������
	 */
	private function afterReceivedHeaders(){
		//�����ض������û��set-cookie�������ڷ�����������ض��򣬵������ƴ���
		if($this->redirect && $this->requestMethod!='HEAD' && in_array($this->responseStatusCode,array(301,302)) && $this->leftRedirectCount>0 && !empty($this->responseHeaders['location']) && empty($this->responseHeaders['set-cookie'])){
			$this->newLocation=$this->responseHeaders['location'];
			$this->leftRedirectCount--;
			return true;
		}

		$totalLen=$this->contentLength=(int)$this->getResponseHeader('content-length', -1);
		if($this->contentLength===-1){
			$range = $this->getResponseHeader('Content-Range', '');
			if($range && preg_match('#^bytes\s+(\d+)\-(\d+)/(\d+)$#', $range, $match)){
				$this->contentLength = (int)$match[2]-(int)$match[1]+1;
				$totalLen = (int)$match[3];
			}
		}
		if($this->allContentLength==0 && $totalLen>=0) $this->allContentLength=$totalLen;

		$this->onReceivedHeader($this->responseHeaders, false);
		if($this->shouldStop || $this->lastError){
			return false;
		}

		//�����֧�ֶϵ�����
		if(($this->isText || $this->shouldUnzip) && $this->receivedLength>0 && ($this->responseStatusCode==200 || !$this->checkResponseHeader('Content-Range'))){
			$this->receivedLength = 0;
			$this->responseBody = null;
		}

		return true;
	}

	/**
	 * ������Ӧͷ�¼����������������0����ֹcurl
	 * @param resource $handle
	 * @param string $line
	 * @return number
	 */
	private function writeHeader($handle, $line) {
	    if($this->logFileHandle && empty($this->headers)){
	        $this->addHttpLog("\n< " . time() . " writeHeader\n");
	    }

		$this->headers.=$line;
		if(trim($line)=='' && $this->proxy && stripos($this->headers,'200 Connection established')!==false){
			//��ͨ������ʱ������᷵��httpͷ��Զ�̷�����Ҳ��Ҫ����httpͷ��������Ҫ�Ѵ����ص�httpͷȥ��
			$this->headers='';
		}elseif(trim($line)==''){
			$this->responseStatusText = null;
			$this->responseStatusCode = 0;
			$this->responseHeadersText = null;
			$this->responseHeaders = array('set-cookie'=>array(),);
			$this->contentType = $this->charset = null;
			$this->parseResponseHeaders($this->headers);
			if($this->responseStatusCode<=0) return 0;
			if(!$this->afterReceivedHeaders()){
				return 0;
			}
			$this->headers = '';
			if($this->shouldStop || $this->newLocation) return 0;
		}
		$this->preserveTimeout();
		return strlen($line);
	}

	/**
	 * ������Ӧ���¼����������������0����ֹcurl
	 * @param resource $handle
	 * @param string $data
	 * @return number
	 */
	private function writeBody($handle, $data) {
		if($this->shouldStop || connection_aborted()){
			$this->lastError='cancel';
			return 0;
		}
		$this->preserveTimeout();
		if($this->shouldUnzip){
			$this->responseBody.=$data;
		}else{
			$this->onReceivedBody($data, false, false);
			$this->preserveTimeout();
		}

		$len = strlen($data);
		$this->receivedLength += $len;

		if($this->logFileHandle){
		    $this->addHttpLog("\n< " . time() . ' writeBody ' . strlen($data));
		}

		return $len;
	}

	private function onProgress($download_size, $downloaded, $upload_size, $uploaded){
	}

	protected function doRequest(){
		$this->headers=null; //����ȡhead�Ĺ�������ʱ����head��Ϣ���ڽ��ղ��������֮��������
		$this->keepAlive=false;
		$this->allData=null;
		$this->receivedLength=0;
		$this->allContentLength=0;
		$this->startTime=0;
		$this->curlHandle=0;
		$this->newLocation=null;
		$this->leftRedirectCount=self::MAX_REDIRECTS;

		$start_options = array(
			//�±����������ڽ��������в���Ч��ֻ��Ϊ�������CURLOPT_TIMEOUTʹ��
			CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
			//�±�����������curl������ִ��ʱ�䣬���������curlִ����;������ĺ�ʱ���Ǹ���ʱ�ڼ��ǲ����жϽű��ģ����ǻ�����Mcurl��ִ��ʱ����
			//���ԣ����������ʱָ��Ϊ���ӳ�ʱֵ����HEADERFUNCTION��ʼ������Ϊһ�ζ�ȡʱ�䣬��ÿ��WRITEFUNCTIONʱ������һ�ζ�ȡʱ��
			//�������ã��ȿ���ʹ�����Ӳ����ܼ�ʱ��ʱ��Ҳ�ܱ������ش��ļ�ʱ���ز������ͳ�ʱ������
			CURLOPT_TIMEOUT => $this->connectTimeout+2,
			CURLOPT_USERAGENT => $this->getRequestHeader('user-agent'),
			CURLOPT_BUFFERSIZE => HTTP_BUFFERING,
			CURLOPT_SSL_VERIFYHOST => false,
			CURLOPT_SSL_VERIFYPEER => false,
		    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
			CURLOPT_FRESH_CONNECT => false,
			CURLOPT_FORBID_REUSE => false,
			CURLOPT_DNS_CACHE_TIMEOUT => 600,
			CURLOPT_HEADER => false,
			CURLOPT_RETURNTRANSFER => true,  //trueʱ�����ص��ַ�����������ص��������¼��ﴦ��
			CURLOPT_HEADERFUNCTION => array($this,'writeHeader'),
			CURLOPT_WRITEFUNCTION => array($this,'writeBody'),
			//CURLOPT_NOPROGRESS => false,
			//CURLOPT_PROGRESSFUNCTION => array($this,'onProgress'),
		);

		if($this->logFileHandle){
			$start_options[CURLOPT_VERBOSE] = true;
			$start_options[CURLOPT_STDERR] = $this->logFileHandle;
		}

		if($this->proxy && $this->url->host!='localhost' && $this->url->host!='127.0.0.1') {
			$start_options[CURLOPT_PROXYTYPE] = strpos($this->proxy,'socks5:')===0 ? CURLPROXY_SOCKS5_HOSTNAME : CURLPROXY_HTTP;
			$start_options[CURLOPT_HTTPPROXYTUNNEL] = $start_options[CURLOPT_PROXYTYPE]==CURLPROXY_HTTP && $this->url->scheme=='https';
			$start_options[CURLOPT_PROXY] = str_replace('socks5:', '', $this->proxy);
		}

		$isPartialRequest = $this->checkRequestHeader('Range');
		$retry_count=0;
		$handle = 0;
		do {
			$retry = false;
			$this->lastError=null;
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);

			if($this->logFileHandle){
			    $this->addHttpLog("\n< " . time() . " curl_init \n");
			}

			$this->curlHandle = $handle = curl_init();
			if(!$this->curlHandle){
				$this->lastError=501;
				return false;
			}

			$options=$start_options;
			$this->lastUrl = $this->url->url;
			$options[CURLOPT_URL] = $this->url->url;
			$options[CURLOPT_HTTPHEADER] = $this->prepareRequqestHeaders(false,'array');

			switch($this->requestMethod){
				case 'HEAD':
					$options[CURLOPT_NOBODY] = true;
					break;
				case 'GET':
					$options[CURLOPT_HTTPGET] = true;
					break;
				case 'POST':
					$options[CURLOPT_POST] = true;
					$options[CURLOPT_POSTFIELDS] = $this->postData;
					break;
				case 'PUT':
					$options[CURLOPT_CUSTOMREQUEST] = 'PUT';
					$options[CURLOPT_POSTFIELDS] = $this->postData;
					break;
			}

// 			//���ڱ�����������һ�ֽ�����һ���ֵ���������������ҳ��Ҳ��������̬�������ڶ�����Գ�������
// 			if($this->receivedLength>0 && !$isPartialRequest &&
// 				$this->getResponseHeader('Accept-Ranges')=='bytes' &&
// 				stripos($this->contentType,'text/html')===false && strpos($this->lastUrl,'?')===false)
// 			{
// 				//���Զϵ�����
// 				$options[CURLOPT_RESUME_FROM] = $this->receivedLength;
// 			}

			curl_setopt_array($handle, $options);
			@curl_setopt($handle, CURLOPT_FOLLOWLOCATION, false);
			//@curl_setopt($handle, CURLOPT_MAXREDIRS, self::MAX_REDIRECTS);

			//�������󣨷���������writeHeader��writeBody�������¼��ﴦ��
			//������Ӧͷ�ж��Ƿ�Ӧ�ü���������Ӧ�壬��writeHeader�¼���ʵ������ֹ����
			$this->startTime=microtime(true);
			$ret = curl_exec($handle);

			//������������ض���
			if($this->newLocation) {
			    if($this->logFileHandle){
			        $this->addHttpLog("\n< " . time() . ' newLocation ');
			    }

				$this->lastError=null;
				$retry=true;
				if($this->leftRedirectCount<=0){break;}
				$this->requestMethod='GET';
				$this->responseStatusCode=0;
				$url = $this->url->getFullUrl($this->newLocation,true);
				$this->url = Url::create($url);
				$this->newLocation = null;
				$this->receivedLength = 0;
				curl_close($handle);
				$this->curlHandle = $handle = 0;
				if(!$this->url) {$this->lastError=400; return false;}
				continue;
			}

			if(!$this->lastError){
				$errno = curl_errno($handle);
				switch ($errno){
					case CURLE_OK:
						$this->lastError=null;
						break;
					case CURLE_UNSUPPORTED_PROTOCOL:
					case CURLE_URL_MALFORMAT:
						$this->lastError=501;
						break;
					case CURLE_COULDNT_RESOLVE_PROXY:
					case CURLE_COULDNT_RESOLVE_HOST:
					case CURLE_COULDNT_CONNECT:
					case CURLE_SSL_CONNECT_ERROR:
					case CURLE_OPERATION_TIMEOUTED:
						$this->lastError = $this->receivedLength>0 ? 'partial' : (is_null($this->headers)?'internet':'timeout');
						break;
					case CURLE_PARTIAL_FILE:
						$this->lastError=206;
						break;
					case CURLE_RECV_ERROR:
						$retry=true;
						$retry_count++;
						$this->lastError=500;
						break;
					default:
						$this->lastError = $errno . '. ' . curl_error($handle);
						break;
				}
			}
			curl_close($handle);

			if($this->logFileHandle){
			    $this->addHttpLog("\n< " . time() . ' curl_close ');
			}

			if(connection_aborted()){
				return false;
//			}elseif(($this->lastError=='internet' || $this->lastError==206) && $this->requestMethod!='HEAD' && $retry_count<$this->maxRetry) {
			}elseif($this->lastError=='internet' && $this->receivedLength==0) {
				//���Ӵ���ʱ����
				$retry=true;
				$retry_count++;
				continue;
			}elseif($this->lastError && !$retry){
				break;
			}
		} while ($retry && $retry_count<=$this->maxRetry);

		$finished = !$this->lastError && (in_array($this->responseStatusCode, array(100,101,200,204,301,302,304)) || ($this->allContentLength>0 && $this->receivedLength>=$this->allContentLength));
		if($finished){
			$this->lastError=null;
		}

// 		if($finished && !$isPartialRequest && $this->responseStatusCode==206){
// 			$this->contentLength=$this->allContentLength;
// 			$this->responseStatusCode=200;
// 			$this->responseHeadersText = preg_replace(
// 				array('#^HTTP/1\.[01]\s206\s[^\r\n]+#i', '#Content-Length:\s*\d+\s+#i', '#Content-Range:\s*[^\r\n]+#i'),
// 				array('HTTP/1.1 200 OK', '', "Content-Length: {$this->allContentLength}"),
// 				$this->responseHeadersText);
// 			$this->parseResponseStatus($this->responseHeadersText);
// 		}

		//���$finished=trueʱ����ʾ�Ѿ��������������ݣ�
		//1. �������Ҫ��ѹ��writeBody����ܰ������ݣ���Ҫ�������ظ�������
		//2. �����Ҫ��ѹ����ҳ������writeBody���û���κ����ݷ��ظ������ߣ���Ҫ��ѹ���ٷ��������ߣ�û���������Ĳ��ܽ�ѹ��
		if($this->shouldUnzip){
			if($finished){
			    if($this->logFileHandle){
			        $this->addHttpLog("\n< " . time() . ' unzip');
			    }
				$allContent=$this->unzip($this->responseBody, $this->responseHeaders['content-encoding']);
			}else{
				$allContent=null;
				$this->lastError = $this->lastError?$this->lastError:'timeout';
			}
		}else{
			$allContent=$this->responseBody;
		}
		$this->responseBody=null;

		if($this->logFileHandle){
		    $this->addHttpLog("\n< " . time() . ' before onReceivedBody');
		}

		$this->onReceivedBody($allContent, $finished, false);

		if($this->logFileHandle){
		    $this->addHttpLog("\n< " . time() . " after onReceivedBody\n");
		}

		return !$this->lastError;
	}
}

/**
 * ʹ�� fopen ����ʵ��httpЭ��
 */
class HttpFopen extends Http {
	protected function onCreate() {
	}

	protected function onDestroy($force=false) {
	}

	function stream_notification_callback($notification_code, $severity, $message, $message_code, $bytes_transferred, $bytes_max) {
		if($notification_code==STREAM_NOTIFY_REDIRECTED){
			$this->lastUrl = $this->url->getFullUrl($message, true);
		}
	}

	protected function doRequest(){
		//HTTP context options  http://php.net/manual/en/context.http.php
		$options = array($this->url->scheme =>
			array(
				'method' => $this->requestMethod,
				'header' => $this->prepareRequqestHeaders(false,'string'),
				'user_agent' => $this->getRequestHeader('User-Agent'),
				'content' => $this->requestMethod=='POST' ? $this->postData : '',
			    'proxy'	=> $this->proxy && $this->url->host!='localhost' && $this->url->host!='127.0.0.1' ? 'tcp://'.str_replace('socks5:', '', $this->proxy) : '',
				'follow_location'=>$this->redirect?1:0,
				'max_redirects' => self::MAX_REDIRECTS,
				'request_fulluri' => !empty($this->proxy),
				'protocol_version' => 1.0,
				'timeout' => $this->connectTimeout+$this->readTimeout,
				'ignore_errors' => true,
			    'verify_peer' => false,
			    'verify_peer_name' => false,
			    'allow_self_signed' => true,
			)
		);

		$context = stream_context_create($options);
		@stream_context_set_params($context, array("notification" => array($this,"stream_notification_callback")));

		//���ýű���ʱ
		if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);
		//����
		$this->lastUrl = $this->url->url;
		if($this->logFileHandle){
			$this->addHttpLog("\n>>> HttpFopen��\n");
			$this->addHttpLog($context);
			$this->addHttpLog("\n\n");
		}
		$handle = fopen($this->url->url, 'r', false, $context);
		if (!$handle){
			$this->lastError = 'http request failed! Could not open handle for fopen() to the remote.';
			return false;
		}
		//������Զ�˷�����֮���stream������ʱ
		stream_set_timeout($handle, intval($this->readTimeout));
		if($this->shouldStop) return false;

		//���ýű���ʱ
		if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		//������Ӧͷ
		$meta = stream_get_meta_data($handle);
		if($this->logFileHandle){
			$this->addHttpLog("\n<<<\n");
			$this->addHttpLog($meta);
			$this->addHttpLog("\n\n");
		}
		if($meta['timed_out']){
			$this->lastError='internet';
			fclose($handle);
			return false;
		}else{
			$this->parseResponseHeaders(implode("\n",isset($meta['wrapper_data']['headers'])?$meta['wrapper_data']['headers']:$meta['wrapper_data']));
			if($this->responseStatusCode<=0){
				$this->lastError='timeout';
				fclose($handle);
				return false;
			}
			$this->contentLength = (int)$this->getResponseHeader('content-length', -1);

			if($this->logFileHandle){
				$this->addHttpLog("<<<\n");
				$this->addHttpLog($this->responseHeadersText);
				$this->addHttpLog("\n\n");
			}

			//֪ͨ�������յ�HTTPͷ
			$this->onReceivedHeader($this->responseHeaders, false);
			if($this->shouldStop || $this->lastError){
				fclose($handle);
				return false;
			}

			//�κβ�������Ϣ�����Ϣ����1XX��204��304��50X����Ӧ��Ϣ���κ�ͷ(HEAD���ײ�)�������Ӧ��Ϣ����������һ�����У�CLRF��������
			if($this->requestMethod=='HEAD' || in_array($this->responseStatusCode, array(100,101,204,301,302,304)) || $meta['eof']){
				$this->onReceivedBody(null, true, false);
				fclose($handle);
				return true;
			}
		}

		if($this->lastError || $this->shouldStop) return false;
		@stream_context_set_params($context, array("notification" => null));

		//������Ӧ��
		$chunked=strtolower($this->getResponseHeader('transfer-encoding'))=='chunked';
		$finished=false;
		$allContent='';
		while (!feof($handle) && !$this->shouldStop && !connection_aborted()) {
			if($chunked){
				$line=stream_get_line($handle, 100);
				if($line===false){
					$this->lastError='timeout';
					fclose($handle);
					return false;
				}
				$toread = hexdec(trim($line));
				if($toread===0) {
					$finished=true;
					break;
				}else{
					$data=stream_get_contents($handle, $toread);
					stream_get_line($handle, 100);
				}
			}else{
				$data=stream_get_contents($handle, HTTP_BUFFERING);
			}

			if($data===false && !feof($handle)){
				$this->lastError='timeout';
				fclose($handle);
				return false;
			}elseif($this->shouldUnzip){
				$allContent.=$data;
			}else{
				$this->onReceivedBody($data, false, false);
			}

			//���ýű���ʱ
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		}

		$finished = $finished || ($this->contentLength>0 && strlen($allContent)>=$this->contentLength) || feof($handle);
		$context=null;
		fclose($handle);
		$handle=null;
		if($this->shouldStop || connection_aborted()) return false;

		if($this->shouldUnzip){
			//��ѹ����������Ҫ�����ʱ�Ƚ��н�ѹ��û���ʱ���ܷ��ظ�������
			if($finished){
				$allContent=$this->unzip($allContent, $this->responseHeaders['content-encoding']);
				$this->onReceivedBody($allContent, true, false);
			}else{
				$this->lastError='timeout';
				return false;
			}
		}else{
			$this->onReceivedBody('', true, false);
		}
		return true;
	}
}

/**
 * ʹ�þ���
 * $http = Http::create();
 * $http->cacheDir = '/temp';
 * $http->readCache = true;
 * if(false !== ($response = $http->get('http://www.google.com/'))) {
 * 	$status = $http->getStatus();
 * 	$headers = $http->getResponseHeader();
 * 	$cookie = $http->getResponseCookie();
 * }
 * $http = null;
 */
abstract class Http {
	const MAX_REDIRECTS=5;
	protected $requestVersion, $requestMethod, $requestHeaders, $postData, $postFields, $postFiles, $requestRange;
	protected $responseStatusText, $responseStatusCode, $responseHeaders, $responseHeadersText;
	protected $url, $lastUrl;
	protected $shouldStop;
	protected $ignore404=true; //��Ϊtrueʱ���������404״̬���Ͳ��ٽ���������
	public $responseBody;
	public $contentLength;
	public $currentHome;
	public $connectTimeout = 5;
	public $readTimeout = 5;
	public $maxRetry = HTTP_MAX_RETRIES;
	public $isText=false;
	public $shouldUnzip=false;
	/**
	 * �±������ص������������������Ϊnull������������������ͨ������������Ǵ˶���ķ���
	 */
	protected $sender = null;
	/**
	 * ��������HTTPͷ��֮����¼���������$http, $headers, $fromCache
	 */
	protected $receivedHeaderCallback = null;
	/**
	 * ����ÿ���HTTP����ʱ���¼���������$http, $data, $finished, $fromCache
	 */
	protected $receivedBodyCallback = null;
	//��־�ļ����
	protected $logFileHandle = null;

	/*
	 * ������ҳ��content-type (������charset)
	 */
	public $contentType;
	/*
	 * ������ҳ��charset
	*/
	public $charset;

	/**
	 * �Ƿ��Զ�ת��
	 */
	public $redirect = true;
	/**
	 * ���ػ���Ŀ¼��Ĭ�ϱ��浽 TEMPDIR ��ڼ��㻺���ļ���ʱ����ʹ�� $cacheDir���������ַ��cacheSalt��cacheExt ��ϼ�����ã�
	 */
	public $cacheDir = TEMPDIR;
	/**
	 * ���������Ķ������ԣ��ڼ��㻺���ļ���ʱ����ʹ�� $cacheDir���������ַ��cacheSalt��cacheExt ��ϼ�����ã�
	 */
	public $cacheSalt = null;
	/**
	 * ���ػ�����չ�����ڼ��㻺���ļ���ʱ����ʹ�� $cacheDir���������ַ��cacheSalt��cacheExt ��ϼ�����ã�
	 */
	public $cacheExt = null;
	/**
	 * �Ƿ���ʵ�ʷ���HTTP����֮ǰ�ȼ���Ƿ��п��õı��ػ��棬
	 * ���ڵõ�ʵ�ʵ�HTTP��Ӧʱ�Ƿ�д�뻺�棬���ڵ���������ʵ�֣����ڱ�������ʵ��
	 * û�жԻ�����ռ�õ��ܴ��̿ռ���м�飬ֻ�е�����ʣ��ռ��㹻����Ӧ��ʱ�Ž��鿪����
	 */
	public $readCache = false;
	/**
	 * ��ȡ����ʱ��������泬���˴�ʱ�䣬����Ϊ�Ѿ�������
	 */
	public $cacheExpire = 0;
	/**
	 * ���ô��������������  127.0.0.1:8010
	 */
	public $proxy = null;
	/**
	 * ���һ�η����Ĵ���
	 */
	public $lastError = null;

	//���󷽷� (�����಻Ҫ���Լ��Ĺ��캯�����������������Ҷ�Ҫʵ�������⼸������)
	protected abstract function onCreate();
	protected abstract function onDestroy($force=false);
	protected abstract function doRequest();

	/**
	 * ���ݷ����������Զ�ѡ��httpЭ���ʵ�ַ�ʽ
	 * @param array $config ���ã����԰�����max_file_size, connect_timeout, read_timeout, proxy��û��������Ŀ��ʹ��Ĭ��ֵ��
	 * @return mixed ����ɹ��򷵻ص�ǰ��������֧�ֵ�http�������ʧ�ܾͷ���false
	 */
	public static function create($config=array()){
		$http = null;

		if(isset($config['http_function'])){
			switch($config['http_function']){
				case 'curl':
					$http = new HttpCurl();
					break;
				case 'fsockopen':
				case 'pfsockopen':
					$http = new HttpFsockopen();
					$http->version = $config['http_function'];
					break;
				case 'fopen':
					$http = new HttpFopen();
					break;
			}
		}

		if($http){
			//
		}elseif(extension_loaded('curl') && function_exists('curl_exec')){
			$http = new HttpCurl();
		}elseif(function_exists('fsockopen')){
			$http = new HttpFsockopen();
			$http->version = 'fsockopen';
		}elseif(function_exists('pfsockopen')){
			$http = new HttpFsockopen();
			$http->version = 'pfsockopen';
		}elseif(function_exists('stream_socket_client')){
			$http = new HttpFsockopen();
			$http->version = 'stream_socket_client';
		}elseif (function_exists('ini_get') && in_array(strtolower(ini_get('allow_url_fopen')), array('on','1'))){
			$http = new HttpFopen();
		}else{
			return false;
		}

		//Ĭ������
		if(!isset($config['max_file_size'])) {
			$config['max_file_size']=10;
		}
		if(!isset($config['connect_timeout'])) $config['connect_timeout']=5;
		if(!isset($config['read_timeout'])) $config['read_timeout']=5;
		if(!isset($config['proxy'])) $config['proxy']='';
		if(!isset($config['enable_ssl'])) $config['enable_ssl']=extension_loaded('openssl');
		if(!isset($config['zlib_remote'])) $config['zlib_remote']=extension_loaded("zlib");

		//��������
		if(isset($config['read_cache'])) $http->readCache=$config['read_cache'];
		if(isset($config['cache_dir'])) $http->cacheDir=$config['cache_dir'];
		if(isset($config['cache_expire'])) $http->cacheExpire=$config['cache_expire'];
		if(isset($config['max_retry'])) $http->maxRetry=$config['max_retry'];

		$http->ignore404=isset($config['ignore404'])?(bool)$config['ignore404']:true;
		$http->config=$config;
		$http->proxy=$config['proxy'];
		$http->connectTimeout=$config['connect_timeout'];
		$http->readTimeout=$config['read_timeout'];

		$http->onCreate();
		$http->reset();
		return $http;
	}

	function __destruct(){
		$this->closeHttpLog();
		$this->onDestroy(false);
	}

	/**
	 * ��ÿ���µ�����֮ǰ�����ȳ�ʼ������
	 */
	public function reset() {
		$this->requestVersion = '1.0';
		$this->requestMethod = null;
		$useragent=isset($this->requestHeaders['user-agent']) ? $this->requestHeaders['user-agent'] : null;
		if(!$useragent){
			$useragent=isset($_SERVER['HTTP_USER_AGENT'])?$_SERVER['HTTP_USER_AGENT']:'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)';
		}
		$this->requestHeaders = array(
			'user-agent'=>$useragent,
			'accept'=>!empty($_SERVER['HTTP_ACCEPT'])?$_SERVER['HTTP_ACCEPT']:'*/*;q=0.1',
			'accept-language'=>!empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])?$_SERVER['HTTP_ACCEPT_LANGUAGE']:null,
			'accept-charset'=>!empty($_SERVER['HTTP_ACCEPT_CHARSET'])?$_SERVER['HTTP_ACCEPT_CHARSET']:null,
			'accept-encoding'=>$this->config['zlib_remote']?'gzip,deflate':null,
			'pragma'=>!empty($_SERVER['HTTP_PRAGMA'])?explode(', ', $_SERVER['HTTP_PRAGMA']):null,
			'cookie'=>array(),
			'x-accept-authentication'=>!empty($_SERVER['HTTP_X_ACCEPT_AUTHENTICATION'])?$_SERVER['HTTP_X_ACCEPT_AUTHENTICATION']:null,
			'supported'=>!empty($_SERVER['HTTP_SUPPORTED'])?$_SERVER['HTTP_SUPPORTED']:null,
			'x-flash-version'=>!empty($_SERVER['HTTP_X_FLASH_VERSION'])?$_SERVER['HTTP_X_FLASH_VERSION']:null,
			'x-requested-with'=>!empty($_SERVER['HTTP_X_REQUESTED_WITH'])?$_SERVER['HTTP_X_REQUESTED_WITH']:null,
			'content-type'=>!empty($_SERVER['CONTENT_TYPE'])?$_SERVER['CONTENT_TYPE']:null,
			'expect'=>!empty($_SERVER['HTTP_EXPECT'])?$_SERVER['HTTP_EXPECT']:null,
		);

		$this->postFields = $this->postFiles = array();
		$this->postData = null;
		$this->requestRange = null;

		$this->responseStatusText = null;
		$this->responseStatusCode = 0;
		$this->responseHeadersText = null;
		$this->responseHeaders = array('set-cookie'=>array(),);
		$this->contentType = $this->charset = null;
		$this->responseBody = null;
		$this->contentLength = null;

		$this->lastError = null;
		$this->isText = false;
		$this->shouldUnzip = false;
		$this->shouldStop = false;

		$this->closeHttpLog();
	}

	/**
	 * ֹͣ
	 */
	public function stop(){
		$this->shouldStop = true;
		$this->closeHttpLog();
	}

	/**
	 * ǿ�ƹر�http
	 */
	public function close(){
		$this->onDestroy(true);
		$this->closeHttpLog();
	}

	/**
	 * ֪ͨ�������յ���ȫ����HTTPͷ
	 * @param mixed $header ������������ʽ������δ������ԭʼ�ַ�����ʽ
	 * @param bool $fromCache �����Ƿ���Դ�ڻ���
	 */
	protected final function onReceivedHeader($header, $fromCache=false) {
		if($this->shouldStop) return;
		if(is_array($header)){
			$this->responseHeaders=$header;
		}else{
			$this->parseResponseHeaders($header);
		}

		$this->isText = ($this->contentType && preg_match('#(text/|javascript|json|xml)#i', $this->contentType));
		$this->shouldUnzip = in_array($this->getResponseHeader('content-encoding'), array('gzip','compress','deflate','x-gzip'));

		if(!$fromCache){
			//�����Ч��HTTP״̬��
			if($this->responseStatusCode<=0){
				$this->lastError='timeout';
				return false;
			}
			//�ж��ļ���С�Ƿ񳬳�
			if ($this->requestMethod!='HEAD' &&
				$this->contentLength>0 && $this->config['max_file_size'] && $this->contentLength>$this->config['max_file_size']*1024*1024 &&
				strpos($this->getResponseHeader('Content-Type',''), 'video/')===false) {
				$this->lastError='resource';
				return false;
			}
			//�����״̬��
			$errorCodes = array(403,500,501,502,503,504,505);
			if($this->ignore404) {$errorCodes[]=404; $errorCodes[]=400;}
			if(in_array($this->responseStatusCode, $errorCodes)){
				$this->lastError=$this->responseStatusCode;
				return false;
			}
		}

		if($this->receivedHeaderCallback){
			if(is_object($this->sender)){
				call_user_func(array($this->sender, $this->receivedHeaderCallback), $this, $this->responseHeaders, $fromCache);
			}else{
				call_user_func($this->receivedHeaderCallback, $this, $this->responseHeaders, $fromCache);
			}
		}
	}

	/**
	 * ֪ͨ�������յ��˲���HTTP����
	 * @param string $data
	 * @param bool $finished �����Ƿ񵽴��β
	 * @param bool $fromCache �����Ƿ���Դ�ڻ���
	 */
	protected final function onReceivedBody($data, $finished, $fromCache=false) {
		if($this->shouldStop) return;
		if($this->receivedBodyCallback){
			if(is_object($this->sender)){
				call_user_func(array($this->sender, $this->receivedBodyCallback), $this, $data, $finished, $fromCache);
			}else{
				call_user_func($this->receivedBodyCallback, $this, $data, $finished, $fromCache);
			}
		}else{
			$this->responseBody .= $data;
		}
	}

	/**
	 * �򿪵�����־
	 */
	protected function openHttpLog(){
		if(!empty($_COOKIE['_enable_http_log_']) && defined('APPDIR')){
			static $openLogTimes = 0;
			$logfile = APPDIR.'/temp/http_log.txt';
			if($openLogTimes===0 && @is_writable($logfile) && TIME-filemtime($logfile)>300) {
				@unlink($logfile);
			}
			$openLogTimes++;
			$this->logFileHandle = fopen($logfile, 'a+');
			fwrite($this->logFileHandle, "\r\n\r\n\r\n");
		}
	}
	protected function addHttpLog($content){
		if($this->logFileHandle){
			if(is_array($content)){
				$content = var_export($content, true);
			}
			fwrite($this->logFileHandle, $content);
		}
	}
	protected function closeHttpLog(){
		if($this->logFileHandle){
			if($this->lastError){
				fwrite($this->logFileHandle, "\n\n>>>lastError = {$this->lastError}\n\n");
			}
			fwrite($this->logFileHandle, "\n\n");
			fclose($this->logFileHandle);
			$this->logFileHandle = null;
		}
	}

	/**
	 * �����Ƿ�֧��SSL
	 */
	private function check(){
		if(!$this->checkRequestHeader('user-agent')){
			$this->setRequestHeader('user-agent', 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)');
		}
		if($this->url->scheme=='https' && !extension_loaded('openssl')){
			$this->lastError = 'openssl not supported!';
			return false;
		}else{
			return true;
		}
	}

	/**
	 * HEAD ���� ���Ӳ�ʹ�û��棩
	 * @param string $url
	 * @param array $headers(��ѡ) �����Ϊ�ս�����������ͷ�ϲ����������е�����
	 * @return array ���ؽ���������飬���ʧ�ܾͷ���false
	 */
	public function head($url, $requestHeaders=null){
		$this->requestMethod = 'HEAD';
		$this->url = is_object($url)?$url:Url::create($url);
		if(!$this->check()) return false;
		$this->addRequestHeaders($requestHeaders);
		$this->sender = $this->receivedHeaderCallback = $this->receivedBodyCallback = null;
		$this->openHttpLog();
		if($this->doRequest()){
			$ret = $this->responseHeaders;
			$ret['response-status-code'] = $this->responseStatusCode;
			$ret['response-status-text'] = $this->responseStatusText;
			$ret['response-text'] = $this->responseHeadersText;
			return $ret;
		}else{
			return false;
		}
	}

	/**
	 * GET ���� ��������$cacheDir��������$readCache������cookieΪ��ʱ���ȼ�黺�棩
	 * @param string $url
	 * @param array $headers(��ѡ) �����Ϊ�ս�����������ͷ�ϲ����������е�����
	 * @param object $sender ���ñ������Ķ������Ϊnull�������������������ͨ������������Ǵ˶���ķ���
	 * @param function onReceivedHeader ���յ�������headerʱִ�д˺���������Ϊ��$http, $header
	 * @param function onReceivedBody ���յ�ÿ���bodyʱִ�д˺���������Ϊ��$http, $data, $finished
	 * @return bool �ɹ��ͷ���true��ʧ�ܷ���false
	 * �����Ƿ�ָ����onReceivedHeader����Ӧͷ���ᱣ�浽$responseHeaders�
	 * ���ָ����onReceivedBody����Ӧ���ڴ��¼��ﴦ������ͱ��浽$responseBody��
	 */
	public function get($url, $requestHeaders=null, $sender=null, $onReceivedHeader=null, $onReceivedBody=null){
		$this->requestMethod = 'GET';
		if(!$url){
			$this->lastError = 'url����Ϊ��';
			return false;
		}
		$this->url = is_object($url)?$url:Url::create($url);
		if(!$this->url){
			$this->lastError = 'url��ʽ����';
			return false;
		}
		if(!$this->check()) return false;
		$this->addRequestHeaders($requestHeaders);
		$this->sender = $sender;
		$this->receivedHeaderCallback = $onReceivedHeader;
		$this->receivedBodyCallback = $onReceivedBody;
		$this->openHttpLog();
		return $this->outputCache() ? true : ($this->shouldStop?false:$this->doRequest());
	}

	/**
	 * POST ���� ��������$cacheDir��������$readCache��cookieΪ�ա�����û��Ҫ�ύ������ʱ���ȼ�黺�棩
	 * @param string $url
	 * @param mixed $data Ҫ�ύ�ı����ݣ�������ַ����������б���ֱ���ύ����������齫�������е�ֵ�ϲ����������е�ֵȻ���ٽ��б���
	 * @param array $headers(��ѡ) �����Ϊ�ս�����������ͷ�ϲ����������е�����
	 * @param object $sender ���ñ������Ķ������Ϊnull�������������������ͨ������������Ǵ˶���ķ���
	 * @param function onReceivedHeader ���յ�������headerʱִ�д˺���������Ϊ��$http, $header
	 * @param function onReceivedBody ���յ�ÿ���bodyʱִ�д˺���������Ϊ��$http, $data, $finished
	 * @return mixed �ɹ��ͷ�����Ӧ�壬ʧ�ܷ���false
	 */
	public function post($url, $data=null, $requestHeaders=null, $sender=null, $onReceivedHeader=null, $onReceivedBody=null){
	    $this->requestMethod = 'POST';
		$this->url = is_object($url)?$url:Url::create($url);
		if(!$this->check()) return false;
		$this->addRequestHeaders($requestHeaders);
		if($data){
			if(!is_array($data)){
				if(!empty($this->postFields) || !empty($this->postFiles)){
					$this->lastError = '�Ѿ��������ύ���ݣ�������post��������ָ���ַ�����ʽ���ύ�����ˣ�';
					return false;
				}else{
					$this->postData = $data;
				}
			}else{
				foreach($data as $k=>$v){
					if($k) $this->postFields[$k] = $v;
				}
			}
		}
		$this->buildPostData();
		$this->setRequestHeader('Content-Length', strlen($this->postData));
		$this->sender = $sender;
		$this->receivedHeaderCallback = $onReceivedHeader;
		$this->receivedBodyCallback = $onReceivedBody;
		$this->openHttpLog();
		return $this->outputCache() ? true : ($this->shouldStop?false:$this->doRequest());
	}

	/**
	 * �жϵ�ǰHTTP�����Ƿ�Ӧ��ʹ�û���
	 * @return bool
	 */
	private function shouldCache(){
		return $this->readCache &&
			is_dir($this->cacheDir) &&
			in_array($this->requestMethod, array('GET','POST')) &&
			//empty($this->requestHeaders['cookie']) &&
			!$this->checkRequestHeader('Authorization') &&
			empty($this->postData);
	}

	/**
	 * ��黺���Ƿ��б仯���������������304�ͱ�ʾû�б仯���Ƚ�����Ϊ�˼򵥻�ֻ�������޸�ʱ��
	 * @param CacheHttp $cache
	 * @return bool ��������б仯�ͷ���true��û�仯�ͷ���false
	 */
	private function cacheModified($cache){
		$modified = true;
		$http = clone $this;
		$http->requestMethod = 'HEAD';
		if(isset($cache->headers['last-modified'])){
			$http->setRequestHeader('If-Modified-Since', $cache->headers['last-modified']);
		}
		if(isset($cache->headers['__etag'])){
			$http->setRequestHeader('If-None-Match', $cache->headers['__etag']);
		}
		$http->sender = $http->receivedHeaderCallback = $http->receivedBodyCallback = null;
		$this->openHttpLog();
		if($http->doRequest()){
			if($http->responseStatusCode==304){
				$modified = false;
			}elseif(isset($cache->headers['__etag']) && isset($http->responseHeaders['etag'])){
				$modified = !CacheHttp::matchEtag($http->responseHeaders['etag'], $cache->headers['__etag']);
			}elseif(isset($cache->headers['__last-modified']) && isset($http->responseHeaders['last-modified'])){
				$modified = $cache->headers['__last-modified']!=$http->responseHeaders['last-modified'];
			}elseif(isset($http->responseHeaders['last-modified'])){
				//��ȡԶ�̷��������ļ����޸�ʱ�䣬��Ҫ��ȥԶ�˷������뱾��������ʱ�������߼���������Ϊ10����
				$last_modified = strtotime($http->responseHeaders['last-modified']);
				if($last_modified){
					$date = isset($http->responseHeaders['date'])?(int)strtotime($http->responseHeaders['date']):0;
					$last_modified += $date ? (TIME-$date) : 600;
					$modified = $last_modified>=$cache->mtime;
				}
			}
			if(!$modified){
				if(!$cache->touch()) $modified=true;
			}
		}
		return $modified;
	}

	/**
	 * ��ʾ����������ݣ������ʽҲʹ���¼���ʽ
	 * ��Ϊ����������ݿ����Ǵ�����ģ�HTTP���ص����ݻ���Ҫ���⴦������Ϊ�����֣����¼����и���־��ʾ�Ƿ�����Դ�ڻ���
	 */
	private function outputCache(){
		if($this->shouldCache()){
			$cache = CacheHttp::get($this->cacheDir, $this->url->url, $this->cacheSalt, $this->cacheExt, $this->cacheExpire);
			if($cache && $cache->shouldUpdate) {
				if($this->cacheModified($cache)){
					$cache->close();
					return false;
				}
			}

			if($cache!==false){
				$this->responseHeaders = $cache->headers;
				$this->charset = isset($cache->headers['__charset'])?$cache->headers['__charset']:null;
				if(is_array($this->requestRange)){
					$start=$this->requestRange[0];
					if($start>0) $cache->seek($start);
					$end=$this->requestRange[1];
					if($start>0 || $end!==null){
						$end=intval($end);
						if($end<$start) $end=$cache->contentLength-1;
						$total=$end-$start+1;
						$this->responseHeaders['accept-ranges']='bytes';
						$this->responseHeaders['content-length']=$total;
						$this->responseHeaders['content-range']="bytes {$start}-{$end}/{$cache->contentLength}";
					}else{
						$this->responseHeaders['content-length']=$total=$cache->contentLength;
					}
				}else{
					$this->responseHeaders['content-length']=$total=$cache->contentLength;
				}
				$this->onReceivedHeader($this->responseHeaders, true);
				if($this->shouldStop) {
					$cache->close();
					return false;
				}
				$haveRead=0;
				while(false!==($data=$cache->read(HTTP_BUFFERING))){
					if($this->shouldStop || connection_aborted()) {
						$cache->close();
						exit;
					}
					$this->onReceivedBody($data, false, true);
					$haveRead+=strlen($data);
					if($haveRead>=$total) break;
				}
				$cache->close();
				$this->onReceivedBody(null, true, true);
				return true;
			}else{
				return false;
			}
		}else{
			return false;
		}
	}

	/**
	 * ����ָ����ҳ��Դ����
	 * @param string $url ��ַ
	 * @param string $useragent
	 * @param array $config ���ã����԰�����max_file_size, connect_timeout, read_timeout, proxy��û��������Ŀ��ʹ��Ĭ��ֵ��
	 * @return mixed �����ַ����ʧ�ܾͷ���false������ͷ���HTTPͷ������
	 */
	public static function getHead($url, $useragent, $config=array(), $requestHeaders=array()){
		if(stripos($url,'http://')===false && stripos($url,'https://')===false)
			return false;
		$http = Http::create($config);
		if($http===false){
			return false;
		}
		$http->readCache = false;
		if($useragent){
			$requestHeaders['user-agent'] = $useragent;
		}
		$http->addRequestHeaders($requestHeaders);
		$ret = $http->head($url);
		if(!$ret) $last_http_error = $http->lastError ? $http->lastError : $http->getResponseStatusText();
		$http->close();
		return $ret;
	}

	/**
	 * ����ָ����ҳ��Դ����(����һ��ת�򣬵��ǲ�û���Զ�������һ�����ص�set-cookie)
	 * @param string $url ��ַ
	 * @param string $useragent
	 * @param string $charset �������ݵı��루ԭʼ��ҳ���Զ�ת��Ϊ�˱��룩
	 * @param boolean $returnHeader �Ƿ񷵻�http��Ӧͷ
	 * @param array $config ���ã����԰�����max_file_size, connect_timeout, read_timeout, proxy, charset��û��������Ŀ��ʹ��Ĭ��ֵ��
	 * @return string �����ַ����ʧ�ܾͷ���false������ͷ���ת������������
	 */
	public static function getHtml($url, $useragent, $charset, $returnHeader=false, $config=array(), $requestHeaders=array()){
		if(stripos($url,'http://')===false && stripos($url,'https://')===false)
			return false;
		$http = Http::create($config);
		if($http===false){
			return false;
		}
		if($useragent){
			$requestHeaders['user-agent'] = $useragent;
		}
		$http->addRequestHeaders($requestHeaders);
		$result = $http->get($url);
		if($result){
			$newLocation = $http->getResponseHeader('location');
			if($newLocation){
				$obj = Url::create($url);
				if(!$obj) return false;
				$url = $obj->getFullUrl($newLocation, true);

				$http->close();
				return self::getHtml($url, $useragent, $charset, $returnHeader, $config);
			}
		}
		if($result){
			$content = ($returnHeader?($http->responseHeadersText."\r\n"):'') . $http->responseBody;
			if($charset){
			    $pageCharset = !empty($config['charset']) ? $config['charset'] : $http->charset;
				if(!$pageCharset) $pageCharset=$http->getCharset($content);
				if(!$pageCharset || $pageCharset=='ISO-88509-1') $pageCharset='GBK,BIG5,ASCII,JIS,UTF-8,EUC-JP,SJIS,SHIFT_JIS';
				$charset = strtoupper(trim($charset));
				if($pageCharset!=$charset){
					$content = mb_convert_encoding($content, $charset, $pageCharset);
				}
			}
			$http->close();

			/*
			if($content && $http->readCache && CacheHttp::shouldCache($http->getResponseHeadersText(), TIME)){
				$cache=CacheHttp::create(TEMPDIR, $url, array(), null, 3600, null);
			}
			*/

			return $content;
		}else{
			$last_http_error = $http->lastError ? $http->lastError : $http->getResponseStatusText();
			$http->close();
			return false;
		}
	}

	/**
	 * �ύ����������ҳԴ����
	 * @param string $url ��ַ
	 * @param string $data Ҫ�ύ������
	 * @param string $useragent
	 * @param string $charset �������ݵı��루ԭʼ��ҳ���Զ�ת��Ϊ�˱��룩
	 * @param boolean $returnHeader �Ƿ񷵻�http��Ӧͷ
	 * @param array $config ���ã����԰�����max_file_size, connect_timeout, read_timeout, proxy��û��������Ŀ��ʹ��Ĭ��ֵ��
	 * @return string �����ַ����ʧ�ܾͷ���false������ͷ���ת������������
	 */
	public static function postForm($url, $data, $useragent, $charset, $returnHeader=false, $config=array(), $requestHeaders=array()){
		if(stripos($url,'http://')===false && stripos($url,'https://')===false)
			return false;
		$http = Http::create($config);
		if($http===false){
			return false;
		}
		$http->readCache = false;
		if($useragent){
			$requestHeaders['user-agent'] = $useragent;
		}
		$http->addRequestHeaders($requestHeaders);
		if($http->post($url, $data)){
			$content = ($returnHeader?($http->responseHeadersText."\r\n"):'') . $http->responseBody;
			if($charset){
				$pageCharset = $http->charset;
				if(!$pageCharset) $pageCharset=$http->getCharset($content);
				if(!$pageCharset) $pageCharset='GBK,BIG5,ASCII,JIS,UTF-8,EUC-JP,SJIS,SHIFT_JIS';
				$charset = strtoupper(trim($charset));
				if($pageCharset!=$charset){
					$content = mb_convert_encoding($content, $charset, $pageCharset);
				}
			}
			$http->close();
			return $content;
		}else{
			$last_http_error = $http->lastError ? $http->lastError : $http->getResponseStatusText();
			$http->close();
			return false;
		}
	}

	/**
	 * ����ҳ��������ȡcharset
	 * @param string $content ��ҳ����
	 */
	public function getCharset($content, $charset=''){
		if(!$charset && preg_match('/<meta\s.*?charset\s*=\s*["\']?([\w\-]+)/i', $content, $match)){
			$charset=strtoupper(trim($match[1]));
		}
		$this->charset=strtoupper($charset);
		if(!$this->charset)
			$this->charset='';
		elseif($this->charset=='GB2312' || $this->charset=='CP936' || $this->charset=='MS936')
		$this->charset = 'GBK';
		elseif($this->charset=='BIG5' || $this->charset=='CP950' || $this->charset=='MS950')
		$this->charset = 'BIG-5';
		elseif($this->charset=='UTF8')
			$this->charset = 'UTF-8';
		return $this->charset;
	}

	/**
	 * ���շ��ʵ�url
	 */
	public function getLastUrl(){
		return $this->lastUrl;
	}

	/**
	 * ����Ƿ��Ѿ�������ĳ��HTTP����ͷ
	 */
	public function checkRequestHeader($key){
		$key = strtolower($key);
		if(!$key) return false;
		return isset($this->requestHeaders[$key]);
	}

	/**
	 * ����һ��HTTP����ͷ
	 * @param $key string ����
	 * @param $value string ���Ϊ�ս�ɾ�����ֶ�
	 */
	public function setRequestHeader($key, $value=null) {
		$key = strtolower($key);
		if(!$key || strpos($key,' ')!==false || strpos($key,':')!==false) return;
		if(empty($value)){
			unset($this->requestHeaders[$key]);
			if($key=='range') $this->requestRange=null;
		}else{
			$this->requestHeaders[$key] = strval($value);
			if($key=='range'){
				if(preg_match('#^\s*bytes\s*=\s*(\d+)-(\d+)?$#i', $value, $match)){
					$start=intval($match[1]);
					$end=isset($match[2])?intval($match[2]):null;
					$this->requestRange = array($start, $end);
				}
			}
		}
	}

	/**
	 * ׷��header���鵽HTTP����ͷ
	 * @param array $headers
	 */
	private function addRequestHeaders($headers){
		if(!is_array($headers) || empty($headers)) return;
		foreach($headers as $k=>$v){
			$this->setRequestHeader($k, $v);
		}
	}

	/**
	 * ��ȡHTTP����ͷ��ֵ
	 * @param $key string Ҫ��ȡ�����ƣ����Ϊ�ս���������HTTP����ͷ����
	 * @return mixed �ַ������������ֵ�����ڽ�����null����������
	 */
	public function getRequestHeader($key=null) {
		$key = strtolower($key);
		if(!$key)
			return $this->requestHeaders;
		else
			return isset($this->requestHeaders[$key]) ? $this->requestHeaders[$key] : null;
	}

	/**
	 * ����������֤��Ϣ��Authorizationͷ��
	 * $value string ���Ϊ�գ���ɾ���Ѿ���ӵ�Authorizationͷ
	 */
	public function setAuth($value){
		if($value && stripos($value, 'Basic ')!==0){
			$value = 'Basic '.$value;
		}
		$this->setRequestHeader('Authorization', $value);
	}

	/**
	 * ���һ��cookieֵ������ͷ��
	 */
	public function setCookie($key, $value) {
		if(!$key) return;
		$this->requestHeaders['cookie'][$key] = $value;
	}

	/**
	 * ���cookie�б�����ͷ��
	 */
	public function setCookies($cookies) {
		foreach($cookies as $k=>$v){
			$this->requestHeaders['cookie'][$k] = $v;
		}
	}

	/**
	 * ��HTTP����ͷ���ȡһ��cookie
	 * @param $key string Ҫ��ȡ�����ƣ����Ϊ�ս���������cookie����
	 * @return mixed �ַ������������ֵ�����ڽ�����null����������
	 */
	public function getCookie($key=null) {
		// fetch from last request
		if (!$key)
			return $this->requestHeaders['cookie'];
		else
			return isset($this->requestHeaders['cookie'][$key]) ? $this->requestHeaders['cookie'][$key] : null ;
	}

	/**
	 * �ӷ��������ص�set-cookie��¼����ȡ��Ҫ���´�����ʱ���͵�cookie
	 * @param array $set_cookie
	 * @param string $nexturl
	 * @return array
	 */
	public function getResponseCookies($nexturl){
		$ret = $this->getCookie();
		$cookies = $this->getResponseHeader('set-cookie');
		if(is_array($cookies) && !empty($cookies)){
			$url = Url::create($nexturl);
			foreach($cookies as $cookie){
				$name = $value = $expires = $path = $domain = '';
				preg_match('#^\s*([^=;,\s]*)\s*=?\s*([^;]*)#S', $cookie, $match) && list(, $name, $value)= $match;
				preg_match('#;\s*expires\s*=\s*([^;]*)#iS', $cookie, $match) && list(, $expires)= $match;
				preg_match('#;\s*path\s*=\s*([^;,\s]*)#iS', $cookie, $match) && list(, $path)= $match;
				preg_match('#;\s*domain\s*=\s*([^;,\s]*)#iS', $cookie, $match) && list(, $domain)= $match;
				$path = $path ? $path : '/';
				if ($domain && strpos(".{$url->host}", $domain)===false) {
					continue;
				}
				if ($path && strpos($url->path, $path)!==0) {
					continue;
				}
				if($expires){
					$expires = strtotime($expires);
					if($expires<TIME){
						unset($ret[$name]);
					}
				}
				$ret[$name] = $value;
			}
		}
		return $ret;
	}

	/**
	 * ������ͷ����ת��Ϊ������http����ͷ���ַ���
	 * param bool $includeMethodAndHost �Ƿ񷵻�ǰ���У�method��host��
	 * param string $returnType ��ѡֵ������ 'string' �� 'array'
	 */
	protected function prepareRequqestHeaders($includeMethodAndHost, $returnType){
		$ret=array();
		if($includeMethodAndHost){
			if($this->requestVersion!='1.1' && $this->requestVersion!='1.0') $this->requestVersion!='1.1';
			$ret[]=$this->requestMethod . ' ' . ($this->proxy?$this->url->url:$this->url->uri) . ' HTTP/'. $this->requestVersion;
			$ret[]='Host: ' . $this->url->host . ($this->url->isDefaultPort() ? '' : ':'.$this->url->port);
		}
		foreach($this->requestHeaders as $k=>$v){
			if(empty($v)) continue;
			$name = strtr(ucwords(strtr($k, '-', ' ')), ' ', '-');
			if($k=='cookie' && is_array($v)){
				$cookies='';
				foreach($v as $key=>$value){
					//$cookies .= rawurlencode($key).'='.rawurlencode($value).'; ';
					$cookies .= rawurlencode($key).'='.$value.'; ';
				}
				$v=trim($cookies,' ;');
			}elseif($k=='pragma' && is_array($v)){
				foreach($v as $key=>$value){
					$ret[] = "Pragma: $value";
				}
				continue;
			}elseif(is_array($v)){
				$v=implode('; ', $v);
			}else{
				$v=strval($v);
			}
			if($name && $v) $ret[] = "$name: $v";
		}

		if($returnType=='array'){
			return $ret;
		}else{
			return implode("\r\n", $ret) . "\r\n\r\n";
		}
	}

	// format array field (convert N-DIM(n>=2) array => 2-DIM array)
	private function formatArrayField($value, $pk = NULL) {
		$ret = array ();
		foreach($value as $k => $v) {
			$k = (is_null($pk) ? $k : $pk . $k);
			if (is_array($v))
				$ret += $this->formatArrayField($v, $k . '][');
			else
				$ret[$k] = $v;
		}
		return $ret;
	}

	/**
	 * ���ĳһ��Ҫ�ύ��ֵ
	 * @param $key string ������
	 * @param mixed �ַ��������飬��������齫�ᱻ�Զ�ת��Ϊ arr[key][key2]
	 */
	public function addPostField($key, $value) {
		if(!$key) return;
		if (!is_array($value))
			$this->postFields[$key] = strval($value);
		else {
			$value = $this->formatArrayField($value);
			foreach($value as $k => $v) {
				$k = "{$key}[{$k}]";
				$this->postFields[$k] = strval($v);
			}
		}
	}

	/**
	 * ���һ��Ҫ�ύ���ļ�
	 * @param string $key ����������
	 * @param string $filename Ҫ�ύ���ļ���
	 * @param string ���Ϊ�ղ���$filename��һ����ʵ���ļ������Զ���$filename������
	 */
	public function addPostFile($key, $filename, $content=null) {
		if(!$key) return;
		if (!$content && is_file($filename))
			$content = file_get_contents($filename);
		$this->postFiles[$key] = array(basename($filename),	$content);
	}

	/**
	 * ����Ҫ�ύ���ı�
	 */
	public function setPostData($data){
		$this->postData = $data;
	}

	/**
	 * ���Ҫ�ύ������
	 */
	private function buildPostData(){
		if($this->postData){
			if(!$this->checkRequestHeader('Content-Type')){
				$this->setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
			}
		} elseif (!empty($this->postFiles) && stripos($this->getRequestHeader('Content-Type'),'multipart/form-data')!==false) {
			$boundary = md5($this->url->url . microtime ());
			foreach($this->postFields as $k => $v) {
				$this->postData .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$k}\"\r\n\r\n{$v}\r\n";
			}
			foreach($this->postFiles as $k => $v) {
				$this->postData .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$k}\"; filename=\"{$v[0]}\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n";
				$this->postData .= $v[1] . "\r\n";
			}
			$this->postData .= "--{$boundary}--\r\n";
			$this->setRequestHeader('Content-Type', 'multipart/form-data; boundary=' . $boundary);
		} elseif (!empty($this->postFields)) {
			foreach($this->postFields as $k => $v) {
				$this->postData .= '&' . rawurlencode($k) . '=' . rawurlencode($v);
			}
			$this->postData = substr($this->postData, 1);
			$this->setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		}
	}

	/**
	 * ���һ��HTTP��Ӧͷ
	 */
	public function getResponseHeadersText() {
		return $this->responseHeadersText;
	}

	/**
	 * ���һ��HTTP�����״̬��
	 */
	public function getResponseStatusText() {
		return $this->responseStatusText;
	}

	/**
	 * ���һ��HTTP�����״ֵ̬
	 */
	public function getResponseStatusCode() {
		return $this->responseStatusCode;
	}

	/**
	 * �������������ص�HTTP״ֵ̬��������������� $responseStatus�ֶ���
	 * @param string $str
	 * @return int �ɹ��ͷ���$responseStatusCode��ʧ�ܷ���false
	 */
	protected function parseResponseStatus($str){
		$this->responseHeadersText=trim($str)."\r\n";
		if(preg_match('#^HTTP/[12]\.[01] +(\d+)( +[^\r\n<>]+)?#i', $str, $match)){
			$this->responseStatusText = trim($match[0]);
			$this->responseStatusCode = intval($match[1]);
			return $this->responseStatusCode;
		}else{
			return false;
		}
	}

	/**
	 * �������������ص�HTTPͷ��������������� $responseHeaders �ֶ���
	 * @param string $str
	 * @return array �ɹ��ͷ���$responseHeaders��ʧ�ܷ���false
	 */
	protected function parseResponseHeaders($str){
		$this->responseHeadersText.=$str;
		if(empty($str)){
			return false;
		}else{
			$str=str_replace(array("\r\n","\r"), "\n", $str);
		}
		if(!$this->responseStatusCode){
			$this->parseResponseStatus($str);
		}
		if(preg_match_all('#^([\w\.\-]+): *(.+)$#m', $str, $matches, PREG_SET_ORDER)){
			foreach($matches as $v){
				$key=strtolower($v[1]);
				$value=$v[2];
				if($key=='set-cookie'){
					$this->responseHeaders[$key][] = $value;
				}else{
					$this->responseHeaders[$key] = $value;
					//����Ӧͷ����ȡcontentType��charset
					if($key=='content-type' && !$this->charset){
						if(preg_match('#([a-z0-9+\-\.]+/[a-z0-9+\-\.]+)(?:\s*;\s*charset\s*=\s*([\w\-]+))?#i', $value, $match)){
							$this->contentType = isset($match[1]) ? strtolower($match[1]) : 'text/html';
							$this->charset = isset($match[2]) ? strtoupper($match[2]) : null;
						}else{
							$this->contentType = $value;
						}
						$this->charset=$this->getCharset('', $this->charset);
					}
				}
			}
		}
	}

	public function checkResponseHeader($key){
		$key = strtolower($key);
		if(!$key) return false;
		return isset($this->responseHeaders[$key]);
	}

	public function getResponseHeader($key=null, $default=null){
		$key = strtolower($key);
		if(!$key)
			return $this->responseHeaders;
		else
			return isset($this->responseHeaders[$key]) ? $this->responseHeaders[$key] : $default;
	}

	/*
	 * ����Ӧͷ����ȡ�ļ���
	 */
	public function getFilename(){
		$contentDisposition = $this->getResponseHeader('content-disposition');
		if($contentDisposition && stripos($contentDisposition,'attachment')!==false && preg_match('/\bfilename\s*=\s*[\'"]?([^";\'\r\n]+)/', $contentDisposition, $match)){
			return trim($match[1]);
		}elseif($this->url->file && strpos($this->url->file,'.')>0){
			return $this->url->file;
		}else{
			return null;
		}
	}

	/**
	 * dns���������浽�ļ�
	 * @param $host string ����
	 * @param $force bool �Ƿ�ǿ��ִ�н�����������ȼ����Ч���ڵĻ��棩
	 * @param string �ɹ��򷵻�ip��ʧ���򷵻�host
	 */
	protected function resolve($host, $force=false) {
		//������ʱ����δ�����������ǰ����
		return $host;


		if(preg_match('/^\d+\.\d+\.\d+\.\d+$/', $host)) {
			return $host;
		}

		if($host=='localhost') {
		    return '127.0.0.1';
		}

		$ip = null;
		if ($this->cacheDir) {
			//��ȡ����
			$ips = @file($this->cacheDir.'/dns.~tmp');
			if ($ips === false) {
				$ips=array();
			}elseif(!$force){
				foreach($ips as $k => $v) {
					if (strpos($v, $host . '/') === 0) {
						if (preg_match('#.*?/(\d)/(\d+\.\d+\.\d+\.\d+)\n#', $v, $m) && $m[1] == date('g')) {
							return $m[2];
						} else {
							unset($ips[$k]);
						}
						break;
					}
				}
			}
		}

		//���½���
		$ip = @gethostbyname($host);
		if ($ip != $host) {
			array_unshift($ips, "{$host}/" . date('g') . "/{$ip}\n");
			file_put_contents($this->cacheDir.'/dns.~tmp', implode('',$ips), LOCK_EX);
		}
		return $ip;
	}

	//��ѹ
	protected function unzip($data, $content_encoding){
		if($data && $content_encoding){
			if($content_encoding=='gzip'){
				$s = my_gzdecode($data);
				return $s===false ? $data : $s;
			}elseif($content_encoding=='deflate'){
				$zlibHeader = unpack('n', substr($data, 0, 2));
				if ($zlibHeader[1] % 31 == 0) {
					$s = gzuncompress($data);
				} else {
					$s = gzinflate($data);
				}
				return $s ? $s : $data;
			}
		}
		return $data;
	}


	/**
	 * �ǲ���֩��
	 * @return mixed �������֩��ͷ���false�������֩��ͷ���֩������ƻ����
	 */
	public static function isSpider()
	{
		static $is_spider=null;
		if($is_spider===null) {
			$is_spider=false;
			if (empty($_SERVER['HTTP_USER_AGENT'])){
				$is_spider=false;
			}else{
				//��������֩�������б�ǰ��������������������������ơ���֩�����ҳ��ʱҳ�����ݲ����б���
				$spiders = array(
					'googlebot'=>'google',
					'-google'=>'google',
					'baiduspider'=>'baidu',
					'360spider'=>'360',
					'msnbot'=>'bing',
					'bingbot'=>'bing',
					'yodaobot'=>'yodao',
					'youdaobot'=>'yodao',
					'yahoo! slurp'=>'yahoo',
					'iaskspider'=>'iask',
					'sogou web spider'=>'sogou',
					'sogou push spider'=>'sogou',
					'sosospider'=>'soso',
					'spider jumper'=>'jump',
					'spider'=>'other',
					'crawler'=>'other',
					'mj12bot'=>'other',
					'wget/1.'=>'other',
				);

				$s = strtolower($_SERVER['HTTP_USER_AGENT']);
				foreach ($spiders as $key => $value)
				{
					if (strpos($s, $key)!==false) {
						$is_spider=$value;
						break;
					}
				}
			}
		}
		return $is_spider;
	}

	/**
	 * �ǲ���֩�루�������жϷ�ʽ��
	 * @return boolean
	 */
	public static function isSpider2()
	{
		return preg_match('#(google|spider|bot|slurp|crawler)\W#i', $_SERVER['HTTP_USER_AGENT']);
	}

	/**
	 * �ж��Ƿ���ͨ���ֻ�����
	 * @return bool �Ƿ����ƶ��豸
	 */
	public static function isMobile() {
		static $is_mobile=null;
		if($is_mobile===null) {
			$is_mobile=false;
			// �����HTTP_X_WAP_PROFILE��һ�����ƶ��豸
			if (isset($_SERVER['HTTP_X_WAP_PROFILE']) && $_SERVER['HTTP_X_WAP_PROFILE']) {
				$is_mobile=true;
			}
			//���via��Ϣ����wap��һ�����ƶ��豸,���ַ����̻����θ���Ϣ
			elseif (isset($_SERVER['HTTP_VIA']) && stristr($_SERVER['HTTP_VIA'], "wap")!==false) {
				$is_mobile=true;
			}
			//�Բз����ж��ֻ����͵Ŀͻ��˱�־,�������д����
			elseif (isset($_SERVER['HTTP_USER_AGENT'])) {
				$regex_match='/(ipad|nokia|iphone|android|motorola|^mot\-|softbank|foma|docomo|kddi|up\.browser|up\.link|'.
						'htc|dopod|blazer|netfront|helio|hosin|huawei|novarra|CoolPad|webos|techfaith|palmsource|'.
						'blackberry|alcatel|amoi|ktouch|nexian|samsung|^sam\-|s[cg]h|^lge|ericsson|philips|sagem|wellcom|bunjalloo|maui|'.
						'symbian|smartphone|midp|wap|phone|windows ce|iemobile|^spice|^bird|^zte\-|longcos|pantech|gionee|^sie\-|portalmmm|'.
						'jig\s browser|hiptop|^ucweb|^benq|haier|^lct|opera\s*mobi|opera\*mini|320x320|240x320|176x220'.
						')/i';
				if(preg_match($regex_match, $_SERVER['HTTP_USER_AGENT'])){
					$is_mobile=true;
				}
			}
			//Э�鷨����Ϊ�п��ܲ�׼ȷ���ŵ�����ж�
			elseif(isset($_SERVER['HTTP_ACCEPT']) && ($s=strtolower($_SERVER['HTTP_ACCEPT']))) {
				// ���ֻ֧��wml���Ҳ�֧��html��һ�����ƶ��豸
				// ���֧��wml��html����wml��html֮ǰ�����ƶ��豸
				if (($x=strpos($s, 'vnd.wap.wml')) !== false && (($y=strpos($s, 'text/html')) === false || $x>$y)) {
					$is_mobile=true;
				}
			}
		}
		return $is_mobile;
	}

	/**
	 * ��ȡHTTP����ԭ��
	 * @return string
	 */
	public static function getRawRequest() {
		$raw = '';
		// (1) ������
		$raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
		// (2) ����Headers
		foreach($_SERVER as $key => $value) {
			if(substr($key, 0, 5) === 'HTTP_' && !empty($value)) {
				$key = substr($key, 5);
				$key = strtr($key, '_', ' ');
				$key = ucwords(strtolower($key));
				$key = strtr($key, ' ', '-');
				$raw .= $key.': '.$value."\r\n";
			}
		}
		// (3) ����
		$raw .= "\r\n";
		// (4) ����Body
		$raw .= file_get_contents('php://input');
		return $raw;
	}
}



