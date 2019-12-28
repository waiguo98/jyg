<?php

// 以后考虑使用 Guzzle 替代本组件

/**
* 本页面实现的几个类
* Url url解析类
* FileLock 防止共享冲突的排他型文件锁
* CacheHttp HTTP数据的文件缓存类
* Http 基类和使用不同技术实现HTTP请求的几个派生类（HttpFsockopen HttpCurl HttpFopen）
*
* 纯PHP实现的全功能 Http Client 类(仅在php5下测试，未在php4下测试)
* 1. 纯PHP代码实现，只使用php内置模块和函数，不依赖任何其它第三方库或扩展
* 2. 可以根据服务器环境，从3中实现方法（pfsockopen和fsockopen、cUrl、fopen）中自动选择可用的，每种方法都使用一个独立的派生类实现
* 3. 能设置或读取所有的HTTP头
* 4. 包含全功能并且带有一定智能的COOKIE处理
* 5. 最可贵的一点是，支持 Keep-Alive 的HTTP连接，特别适合一次运行需求多次请求同一主机的内容情况
* 6. 支持通过POST方式上传任意个文件，发送数组字段等
* 7. 支持SSL
* 8. 当存在 is_utf8 和 mb_convert_encoding 函数时，中文url才能被正常下载
*
*/

defined('HTTP_INC_LOADED') or define('HTTP_INC_LOADED', 1);
//应用的临时目录（建议在引入本文件之前使用下行语句统一确定临时文件夹的位置）
defined('TEMPDIR') or define('TEMPDIR', dirname(__FILE__).'/temp');
//HTTP请求最多尝试次数
define ('HTTP_MAX_RETRIES', 3);
//是否启用长连接
define ('PERSISTENT_CONNECTION', 1);
//接收缓存区大小
define('HTTP_BUFFERING', 4096);
//当前时间
defined('TIME') or define('TIME', time());
defined('TODAY') or define('TODAY', date('d',TIME));
//是否禁止了set_time_limit函数
define('ENABLE_SET_TIME_LIMIT', function_exists('set_time_limit'));
//保存最后的http错误响应
$last_http_error = null;

/* 在入口那里应该已经判断过了
if(version_compare(PHP_VERSION, '5.3.3', '<')){
	exit('Need PHP 5.3.3 or higher!');
}
*/


/**
 * 解压函数
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
	 * 递归创建目录
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
	 * 获取文件扩展名(包含.)
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
 * 解析url的各个部分
 */
class Url{
	//以 http://username:password@hostname:8000/path/script?name=value#top 为例，会解析如下：
	public $original;  	//实际请求的原始url
	public $scheme; //协议 http
	public $host; 	//域名 hostname
	public $port; 	//端口 8000
	public $site;	//服务器和非默认端口 hostname:8000
	public $user; 	//用户名 username
	public $pass; 	//密码 password
	public $path; 	//路径 /php/
	public $query;	//参数 name=project
	public $fragment;	//#之后的部分 top
	public $home;   //首页地址 http://localhost:8080
	public $script; //文件绝对路径 /php/user.php
	public $file;   //文件名部分 user.php
	public $uri;	//路径和参数 /php/user.php?name=project
	public $url;  	//完整url（包含域名、路径、参数等，但是不包含#后的内容）
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
	 * 当前网页的完整url (本函数返回的不是伪静态地址，而是动态地址去掉默认的index.php的部分，实际上只使用它的本地路径之前部分的属性)
	 * @return Url 返回当前url的Url对象
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
	 * 如果url解析失败，则返回false
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
		//路径或文件名里包含的中文，需要转换为utf-8之后再进行urlencode编码
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
	 * 当前端口是不是当前协议的默认端口
	 */
	public function isDefaultPort(){
		return isset($this->defaultPorts[$this->scheme]) && $this->defaultPorts[$this->scheme]==$this->port;
	}

	/**
	 * 根据当前网址对象把其他网址转换为完整路径
	 * @param string $url
	 * @param boolean $includeDomain 是否包含协议和域名部分
	 * @param boolean $basePath 基准路径(必须以/开始,以/结尾)
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
					//处理 /./ 和 /../ 把它们转换为直接的地址
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
	 * 获取某个url或域名的顶级域名部分
	 */
	public static function getRootDomain($url){
		if(preg_match('#^(?:https?://)?(?:[\w\-\.]+?\.)?([\w\-\.]{3,}\.(?:com|net|org|gov|[a-z]{2})(?:\.[a-z]{2})?)#i', $url, $match)){
			return strtolower($match[1]);
		}
		return $url;
	}
}

/**
 * 用文件实现的共享锁，需要实例化对象
 * 调用举例：
 * $lock = new FileLock('create_cache');
 * if($lock->lock(60,0)){	//进入锁，超时60秒
 * 	//成功进入锁
 * 	//退出锁
 * 	$lock->unlock();
 * }else{
 * 	//别的线程或进程正在使用这个锁
 * }
 * $lock = null;
 */
class FileLock {
	private $file;
	private $handle;
	private $locked=false;
	private $flockIsValid=false;

	/**
	 * 创建锁
	 * @param string $name 锁名称
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
	 * 检查是否能正确支持flock函数和LOCK_NB参数
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
								//	//据说windows下只有php5.2.1之后才支持LOCK_NB，所以执行到这里肯定就不支持了
								//}else
								if(flock($handle2, LOCK_EX | LOCK_NB)){
									flock($handle2, LOCK_UN); //执行到这里说明上行锁定失败
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
	 * 检查是否可以锁定
	 * @param string $id 锁的名称
	 * @param int $expire 锁的有效期
	 * @return boolean
	 */
	public static function canlock($id, $expire){
		$lock = new FileLock($id);
		$ret = $lock->lock($expire,0);
		if($ret) $lock->unlock();
		return $ret;
	}

	/**
	 * 尝试锁定
	 * @param int $expire 锁的有效期（秒）
	 * @param int $block 阻塞时间（秒）如果为0将不阻塞
	 * @return boolean
	 */
	function lock($expire=0, $block=0){
		if($this->flockIsValid){
			//用文件独占锁作为锁标志
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
			//用文件是否存在作为锁标志
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
	 * 解锁
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
//简单的用文件是否存在作为锁
$handle = fopen(TEMPDIR.'/og.~lck', 'x');
if($handle || filemtime(TEMPDIR.'/og.~lck') < TIME-60){
	//已经入锁
}
if($handle) fclose($handle);
if(file_exists(TEMPDIR.'/og.~lck')) @unlink(TEMPDIR.'/og.~lck');
*/

/**
 * 文件系统缓存
 */
class CacheFile {
	const DEFAULTEXT = '.~tmp';

	/**
	 * 计算缓存文件名
	 */
	private static function getLocalFile($name){
		$id = md5($name);
		$dir = TEMPDIR.'/'.$id{0}.'/'.substr($id,1,2).'/';
		return $dir.'/'.$id.self::DEFAULTEXT;
	}

	/**
	 * 判断缓存是否有效
	 * @param string $name
	 * @param int $expire 缓存有效期（秒）
	 * @return boolean
	 */
	public static function valid($name, $expire=0){
	    $file = self::getLocalFile($name);
	    return file_exists($file) && ($expire<=0 || TIME-filemtime($file)<$expire);
	}
	/**
	 * 获取缓存
	 * @param string $name
	 * @param int $expire 缓存有效期（秒）
	 * @return mixed 如果成功就返回缓存的数据，如果失败就返回false
	 */
	public static function get($name, $expire=0){
		$file = self::getLocalFile($name);
		if(file_exists($file) && ($expire<=0 || TIME-filemtime($file)<$expire)){
			return unserialize(file_get_contents($file));
		}
		return false;
	}
	/**
	 * 写入缓存
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
 * HTTP响应数据的本地文件缓存
 * 1. 如果没有指定缓存的扩展名，文件名为 缓存目录/16位id.~tmp，文件里还额外保存了些信息头，
 *	在清除失效缓存时如果过期将会被删除
 * 2. 如果指定了扩展名，文件名为 缓存目录/16位id.扩展名，文件里没有额外信息，只有缓存数据，
 *	清除失效缓存时如果过期将会被附加 .~000 扩展名，在下次被读取时恢复扩展名并检查更新
 *	如果附加 .~000 扩展名后一直没有被读取，则在下次清除失效缓存时将会被删除
 */
class CacheHttp {
	private $localFile;
	private $hitCount; //保留
	private $headerLength;
	private $handle = null;
	private $lock = null;
	private $forWrite = false;
	private $writeHeader = true;
	public $contentLength;
	public $headers = array();
	public $shouldUpdate = false;
	public $mtime = 0; 					//缓存文件修改时间，也用于在创建时保证等于创建时间，以免无法被客户端首次访问时缓存
	public $cacheext = null;
	const TEMPTAIL = '._temp_';			//临时缓存文件的结尾特征
	const DEFAULTEXPIREOFTEMP = 3600; 	//临时缓存的最长有效期
	const DEFAULTEXT = '.~tmp';			//默认的缓存扩展名
	const PENDINGEXT = '.~000';			//待检验扩展名，必须与上边的DEFAULTEXT长度相同

	/**
	 * 根据HTTP头判断是否应该被缓存
	 * @param array $headers HTTP响应头数组（键值都是小写）
	 * @param bool $pageandjs 网页和js，这两类页面登录后往往有变化，跟别的资源文件的缓存机制不同
	 * @param bool $havecookie 是否有cookie
	 * @return bool 如果可以被缓存就返回计划缓存秒数（网页和js最多1小时，其他最多1天），否则就返回false
	 */
	public static function shouldCache($headers, $pageandjs, $havecookie){
	    $date = isset($headers['date'])?intval(strtotime($headers['date'])):0;
		$localtime = TIME;
		$maxSeconds = $pageandjs ? 3600 : 86400;
        $shortSeconds = 900;

		if(isset($headers['pragma']) && strpos($headers['pragma'],'no-cache')!==false) {
		    //禁止了缓存
			return false;
		}
		if(isset($headers['cache-control'])) {
			$cacheControl = $headers['cache-control'];
			if(preg_match('#no-(?:cache|store)#',$cacheControl)){
			    //禁止了缓存
				return false;
			}elseif($pageandjs && $havecookie && strpos($cacheControl,'public')===false){
                //对于有cookie的网页，继续判断
			}elseif(preg_match('#max-age=(\d+)#',$cacheControl,$match)){
                $seconds = intval($match[1]);
                if($seconds>10){
                    return min($seconds,$maxSeconds);
                }else{
                    //对于缓存秒数小于10秒的，继续判断
                }
			}
		}
		if(isset($headers['expires'])){
		    $expires = $headers['expires']=='-1'?0:strtotime($headers['expires']);
		    if($date && $expires<=$date){
		        //过期时间已经早于服务器当前时间，不应被缓存了
		        return false;
		    }elseif(!$date && $expires-$localtime<600) {
	            //本地时间10分钟之内即将过期，考虑到服务器客户端之间可能存在的时间差，所以把这种情况都视作为不适合被缓存
	            return false;
	        }else{
	            //应该被缓存
	            return min($expires-($date?$date:$localtime), $maxSeconds);
	        }
		}
		if(isset($headers['last-modified'])){
			$lastModified = $headers['last-modified']=='-1'?0:strtotime($headers['last-modified']);
			if($date && $lastModified>=$date) {
			    //修改时间不早于服务器时间，不应被缓存
			    return false;
			}elseif(!$date && $lastModified>$localtime-600){
			    //修改时间比本地时间没超过10分钟，考虑到服务器客户端之间可能存在的时间差，所以把这种情况都视作为不适合被缓存
			    return false;
			}else{
				//应该被缓存
				return min(($date?$date:$localtime)-$lastModified, $maxSeconds);
			}
		}

		$etag = isset($headers['etag']) ? trim($headers['etag'],'" \'') : '';
		$contentDisposition = isset($headers['content-disposition']) ? $headers['content-disposition'] : '';
		if(!$pageandjs && ($etag || strpos($contentDisposition, 'attachment')!==false)){
		    //对于资源文件，如果返回etag或者是下载附件，就认为需要缓存
		    return $maxSeconds;
		}

        $isajax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH']=='XMLHttpRequest';
        if(!$isajax && !$havecookie){
            //如果没有禁止缓存，也不是ajax，也没有cookie，则强制缓存15分钟
            return $shortSeconds;
        }

		//执行到此，基本可以判断为服务器未声明能被缓存
		return false;
	}

	/**
	 * 根据请求信息和服务器缓存里的ETag和Last-Modified的值来判断缓存是否需要更新到客户端去
	 * 检查客户端请求里的etag与服务器上的etag是否相同,
	 * 需要在.htaccess里有类似以下几行的设置（可以合并），$_SERVER里边才能检索到此值
	 * RewriteRule .* - [E=HTTP_IF_NONE_MATCH:%{HTTP:If-None-Match}]
	 * RewriteRule .* - [E=HTTP_IF_MATCH:%{HTTP:If-Match}]
	 * RewriteRule .* - [E=HTTP_IF_MODIFIED_SINCE:%{HTTP:If-Modified-Since}]
	 * @param string $cachedEtag   缓存里的etag值
	 * @return boolean true表示需要从新传输
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
	 * 检查两个etag值是否匹配
	 * @param string $serverEtag
	 * @param string $requestEtag 请求头里的IF_NONE_MATCH值，可能是多个
	 * @return bool
	 */
	public static function matchEtag($serverEtag, $requestEtag){
		$serverEtag = trim(str_replace('W/', '', $serverEtag),' "');
		$requestEtag = str_replace(array('W/','"'), ' ', $requestEtag);
		return strpos(" {$requestEtag} "," {$serverEtag} ")!==false;
	}

	/**
	 * 计算ETag
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
	 * 关闭缓存
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
	 * 计算缓存的ID
	 * @param string $url 要缓存的文件的完整url
	 * @param string $salt 被缓存对象的额外属性
	 * @return string 缓存的ID
	 */
	public static function getCacheID($url, $salt){
		return substr(md5($url.($salt?"\r{$salt}":'')),8,16);
	}

	/**
	 * 计算缓存本地路径
	 * @param string $cacheDir 缓存文件夹（需要自己保证已经建立）
	 * @param string $url 要缓存的文件的完整url
	 * @param string $salt 被缓存对象的额外属性
	 * @param bool $isTemp 临时的缓存文件(临时缓存在完成后会复制到真正的缓存文件)
	 * @param string $ext 缓存文件的扩展名
	 * @return string 缓存文件的完整路径
	 */
	private static function getFile($cacheDir, $url, $salt, $isTemp, $ext=self::DEFAULTEXT){
		$id=self::getCacheID($url, $salt);
		return $cacheDir.'/'.$id{0}.'/'.substr($id,1,2).'/'.$id.($ext?$ext:self::DEFAULTEXT).($isTemp?self::TEMPTAIL:'');
	}

	/**
	 * 读取缓存
	 * @param int $size 每次读取的字节数
	 * @return string 返回所读取的缓存，如果文件已经结束则返回false
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
	 * 从当前位置向后移动指针
	 * @param int $offset 向后移动的字节数
	 */
	public function seek($offset){
		return fseek($this->handle,$offset,SEEK_CUR);
	}

	/**
	 * 读取操作是否到了文件结尾
	 * @return bool
	 */
	public function eof(){
		return feof($this->handle);
	}

	/**
	 * 读取缓存
	 * @param string $cacheDir 缓存保存位置
	 * @param string $url 被缓存对象的url
	 * @param string $salt=null 被缓存对象的额外属性（优先使用有此属性的缓存，若不存在则使用无此属性的缓存）
	 * @param string $ext 缓存文件的扩展名
	 * @param int $forceExpire 强制缓存有效期(秒)，0表示使用默认的缓存有效机制
	 * @return mixed 如果成功就返回缓存对象，其文件指针指向内容开始处，如果失败就返回false
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
				//资源文件缓存是否存在待检验文件
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
					//资源文件缓存是否存在与普通缓存里
					$s=substr_replace($cacheFile,self::DEFAULTEXT,-strlen($ext));
					if(file_exists($s)) $localFile = $s;
				}
			}
			if(!$localFile && $salt){
				//缓存是否与域名无关联
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
				//强制过期
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
					//从新检查缓存内容里的url，以避免缓存id算法碰撞造成的问题
					$cache->close();
					return false;
				}
				$cache->headers['etag'] = isset($cache->headers['etag']) ? $cache->headers['etag'] : md5_file($localFile);
				$cache->headers['__ext'] = fileext($url); //远程文件扩展名
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
					'__ext'=>$cache->cacheext, //远程文件扩展名
				);
				if(TIME-$cache->mtime<600) $shouldUpdate=false; //10分钟内不需要重复更新
				$cache->shouldUpdate=$shouldUpdate;
			}

			//缓存过期，检查是否需要更新
			if($cache->shouldUpdate && FileLock::canlock($cache->localFile.self::TEMPTAIL, self::DEFAULTEXPIREOFTEMP)){
				//临时缓存能够锁定，就说明此缓存不是正在更新，返回shouldUpdate=true通知调用者可以更新了；否则就继续使用已经过期了的缓存
				$cache->shouldUpdate = true;
				return $cache;
			}
			return $cache;
		}else{
			return false;
		}
	}

	/**
	 * 创建临时缓存对象，并写入头部信息，如果没有使用append方法写入后续内容，页面结束时临时缓存将会被自动删除
	 * @param string $cacheDir 缓存保存位置
	 * @param string $url 被缓存对象的url
	 * @param array $header 被缓存的HTTP头
	 * @param string $salt 被缓存对象的额外属性（当要为同一个url根据域名或user-agent等不同情况保存不同的缓存时有用）
	 * @param string $expire 缓存有效期（秒），默认3600秒（1小时）
	 * @param string $ext 缓存文件的扩展名
	 * @return mixed 如果成功就返回临时缓存对象，如果失败就返回false
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
	 * 追加缓存的HTTP响应数据的内容 (最后需要调用finish才能完成写入)
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
	 * 仅更新缓存文件的修改日期
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
	 * 完成了HTTP响应数据的保存，只有此时才会把临时缓存转储到真正的缓存
	 * 如果成功，就返回缓存文件的完整名称
	 */
	public function finish(){
		$ret = null;
		if($this->contentLength>0){
			if($this->writeHeader){
				fseek($this->handle, 5+5, SEEK_SET);
				fwrite($this->handle, str_pad(base_convert($this->contentLength,10,36), 10));
			}
			$new = substr($this->localFile, 0, 0-strlen(self::TEMPTAIL));

			//怎么防止读写冲突呢（越大和读取越频繁的文件影响越大）
			fclose($this->handle);
			if(!rename($this->localFile, $new)){
				copy($this->localFile, $new);
				@unlink($this->localFile);
			}
			$ret = $new;

			//更新修改时间为为缓存创建时间
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
	 * 清除指定目录下的过期临时文件
	 * 每更换1个路径，或者每隔5秒，或者每删除50个文件，都保存一次清除進度
	 * @param string $dir
	 * @param int $checkTime 缓存的有效检查时间
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

			//跳过已经检查过的文件
			$_full = $dir.'/'.$_f;
			if ($progress['lastpos'] && strcmp(substr($_full,$basedirLen),$progress['lastpos'])<0) {
				continue;
			}

			$time = time();

			//只执行指定时间
			if($time>$progress['endtime']){
				$progress['lock']->unlock();
				fclose($progress['filehandle']);
				exit;
			}

			//保存進度
			if($progress['changeddir']>1 || $time-$progress['progresstime']>=5 || $progress['changedfile']>50){
				$progress['changeddir']=0;
				$progress['changedfile']=0;
				$progress['progresstime']=$time;
				rewind($progress['filehandle']);
				fwrite($progress['filehandle'], str_pad(substr($_full,$basedirLen),10,' '));
			}

			if(is_dir($_full)){
				//子目录
				self::clearMatchFile($_full, $progress);
				$progress['changeddir']++;
			}else{
				$shouldDel=$shouldPending=false;
				if(!$checktime){
					$shouldDel=true;
				}else{
					$ext=substr($_f,$defaultExtPos);
					if($ext==self::DEFAULTEXT){
						//普通缓存（1天没有被使用就删除）
						$shouldDel=(filemtime($_full)<$checktime && fileatime($_full)<$checktime);
					}elseif($ext==self::PENDINGEXT){
						//过期被挂起的缓存（在今天之前挂起的文件将会被删除）
						$shouldDel=date('d',fileatime($_full))!=TODAY;
					}elseif($ext{1}=='~'){
						//其他扩展名以~开头的缓存文件，比如 .~lck .~cok
						$shouldDel=filemtime($_full)<$checktime;
					}else{
						//真实扩展名的缓存（1天没有被修改就挂起，挂起被恢复时会更新文件修改时间）
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
						//防止改名后的文件在本轮被删除
						if(!touch($_full.self::PENDINGEXT, $mtime, $progress['starttime'])){
							touch($_full.self::PENDINGEXT);
						}
					}
				}
			}
		}
	}

	/**
	 * 每天清除1遍过期（超过指定时间没有被使用）的缓存文件
	 * 如果没有当前日期文件，就开始清理
	 * 如果当前日期文件不为空，就从当前日期文件里所记录的当前位置开始继续清理
	 * 如果当期日期文件为空，说明已经清理一遍了，不再清理
	 * @param string $subdir 如果为null则是检查整个缓存目录，否则只检查某个缓存子目录
	 * @param int $expireDay 最后访问时间是几天之前的缓存文件：若为默认扩展名将会被删除，若为真实扩展名将被修改为待检验扩展名，若为待检验扩展名将会被删除；如果此值为0将删除所有缓存文件
	 * @return 删除完成之后返回true
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
                        //磁盘空间满了，清除本目录下的所有缓存
                        clear_temp_dir();
                    }
                }
				exit;
			}
		}elseif(filesize($checkFile)===0){
			if(defined('DISPLAY_CLEARCACHE_LOG')) echo $dir.' 里的过期缓存今天已清理一遍了';
			return true;
		}

		//防止并发(每次清除都计划在13秒内结束)
		$lock = new FileLock('clearOverdueCache');
		if($lock->lock(15, 0)){
			$handle=fopen($checkFile, 'r+');
			if($handle!==false){
				//在删除文件的过程中忽略用户中断和超时
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
				//此目录的缓存清除完毕之后才会执行到这里
				ftruncate($handle, 0);
				fclose($handle);
				$lock->unlock();
				if(defined('DISPLAY_CLEARCACHE_LOG')) echo $dir.' 里的过期缓存已清理完毕';
			}
			$lock->unlock();
			return true;
		}else{
			if(defined('DISPLAY_CLEARCACHE_LOG')) echo '其它请求正在执行清除缓存任务';
		}
		return false;
	}

	/**
	 * 是否应该清除此缓存子目录
	 * @param string $subdir 如果为null则是检查整个缓存目录，否则只检查某个缓存子目录
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
 * 使用 pfsockopen 或 fsockopen 实现http协议
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
	 * 连接远程服务器
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
				//flag参数: STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT
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
	 * 接收响应头
	 * @return bool
	 */
	private function receiveResponseHeaders(){
		$headerText='';
		while(!$this->shouldStop && $this->active() && !$this->eof()){
			//设置脚本超时
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);

			$line=fgets($this->socket, 1024);
			if($line===false){
				//失败
				return false;
			}elseif(!$this->responseStatusCode){
				//上次的请求没有返回完毕，我们抛弃它
				$this->parseResponseStatus($line);
			}elseif(trim($line)==''){
				//如果是空行说明响应头结束
				break;
			}else{
				//响应头
				$headerText.=$line;
			}
		}
		if($this->shouldStop || !$this->responseStatusCode) return false;
		$this->parseResponseHeaders($headerText);

		if($this->redirect && $this->requestMethod!='HEAD' && in_array($this->responseStatusCode,array(301,302)) && $this->leftRedirectCount>0 && !empty($this->responseHeaders['location']) && empty($this->responseHeaders['set-cookie'])){
			//遇到重定向，如果没有set-cookie，则尽量在服务器端完成重定向，但有限制次数
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
	 * 接收正文
	 * @return bool 是否成功收取了全部的正文
	 */
	private function receiveResponseBody(){
		$allContent='';
		$finished=false;
		$haveRead=0;
		$toread=0;
		while(!$this->shouldStop && !connection_aborted() && $this->active() && !$this->eof()){
			if($this->chunked && $toread>0){
				//继续
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

			//设置脚本超时
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
				//被压缩的数据需要在完成时先进行解压，没完成时不能返回给调用者
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
		$this->addHttpLog("\n>>> version：{$this->version}\n");
		do {
			$retry = false;
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);

			$this->lastUrl = $this->url->url;
			if($lastHost!=$this->url->host){
				$lastHost=$this->url->host;
				$this->remoteIp=$this->resolve($lastHost);
				$this->addHttpLog("\n>>> 解析域名：{$lastHost} => {$this->remoteIp}\n");
			}
			$requestHeader=$this->prepareRequqestHeaders(true, 'string');
			$postData=$this->requestMethod=='POST' ? $this->postData : null;
			//== 连接远程服务器 ==
			if(!$this->socket && !$this->connect()){
				if($retry_count===1){
					//如果第一次连接失败，就强制解析一下域名
					$this->remoteIp=$this->resolve($this->url->host, true);
					$this->addHttpLog("\n>>> 解析域名：{$this->url->host} => {$this->remoteIp}\n");
				}
				$retry=true;
				$retry_count++;
				continue;
			}
			$this->addHttpLog("\n>>> 连接服务器：".($this->socket ? '成功' : '失败')."\n");
			if($this->shouldStop) return false;
			//== 发送HTTP请求 ==
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);
			$this->addHttpLog("\n>>> 请求：\n{$requestHeader}");
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
			//== 提交post数据 ==
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
			//== 设置脚本超时和socket读取超时 ==
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
			stream_set_timeout($this->socket, $this->readTimeout); //针对某一次fgets或fread的超时
			//== 接收HTTP头 ==
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
			//== 服务器端完成重定向
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
			//== 成功接收到HTTP头
			$this->lastError=null;
		} while ( $retry && $retry_count<$this->maxRetry );

		//是否成功收到HTTP头
		if($this->lastError){
			$this->disconnect();
			return false;
		}

		//通知调用者收到HTTP头
		$this->onReceivedHeader($this->responseHeaders, false);
		if($this->shouldStop || $this->lastError){
			$this->disconnect();
			return false;
		}

		//任何不含有消息体的消息（如1XX、204、304、50X等响应消息和任何头(HEAD，首部)请求的响应消息），总是由一个空行（CLRF）结束。
		if($this->requestMethod=='HEAD' || in_array($this->responseStatusCode, array(100,101,204,301,302,304))){
			$this->disconnect();
			$this->onReceivedBody(null, true, false);
			return true;
		}

		//接收响应体
		return $this->receiveResponseBody();
	}
}

/**
 * 使用 cUrl 模块实现http协议
 * 有可能服务器想返回的就是206信息，所以当接收到一部分数据时，不能再重复请求了，这部分代码暂时禁用掉
 */
class HttpCurl extends Http {
	private $headers=null; //在收取head的过程中临时保存head信息，在接收并分析完毕之后就清除了
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
	 * 保证cur的执行时间还剩余一次读取超时时间
	 */
	private function preserveTimeout(){
		if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		$sec = ceil(microtime(true)-$this->startTime) + $this->readTimeout;
		curl_setopt($this->curlHandle, CURLOPT_TIMEOUT, $sec);
	}

	/**
	 * 当全部HTTP接收完成时,返回false将停止本次请求
	 */
	private function afterReceivedHeaders(){
		//遇到重定向，如果没有set-cookie，则尽量在服务器端完成重定向，但有限制次数
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

		//如果不支持断点续传
		if(($this->isText || $this->shouldUnzip) && $this->receivedLength>0 && ($this->responseStatusCode==200 || !$this->checkResponseHeader('Content-Range'))){
			$this->receivedLength = 0;
			$this->responseBody = null;
		}

		return true;
	}

	/**
	 * 接收响应头事件，如果本函数返回0将终止curl
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
			//当通过代理时，代理会返回http头，远程服务器也需要返回http头，我们需要把代理返回的http头去除
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
	 * 接收响应体事件，如果本函数返回0将终止curl
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
		$this->headers=null; //在收取head的过程中临时保存head信息，在接收并分析完毕之后就清除了
		$this->keepAlive=false;
		$this->allData=null;
		$this->receivedLength=0;
		$this->allContentLength=0;
		$this->startTime=0;
		$this->curlHandle=0;
		$this->newLocation=null;
		$this->leftRedirectCount=self::MAX_REDIRECTS;

		$start_options = array(
			//下边这项设置在解析过程中不起效，只作为补充配合CURLOPT_TIMEOUT使用
			CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
			//下边这项设置是curl的完整执行时间，但是如果在curl执行中途发生别的耗时，那个耗时期间是不会中断脚本的，但是会包含進curl的执行时间里
			//所以，我们在最初时指定为连接超时值，在HEADERFUNCTION起始处设置为一次读取时间，在每次WRITEFUNCTION时都设置一次读取时间
			//这样设置，既可以使得连接不上能及时超时，也能避免下载大文件时下载不完整就超时的问题
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
			CURLOPT_RETURNTRANSFER => true,  //true时仅返回到字符串变量里，返回的内容在事件里处理
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

// 			//对于本次请求在上一轮接收了一部分的情况，如果不是网页，也不包含动态参数，第二遍可以尝试续传
// 			if($this->receivedLength>0 && !$isPartialRequest &&
// 				$this->getResponseHeader('Accept-Ranges')=='bytes' &&
// 				stripos($this->contentType,'text/html')===false && strpos($this->lastUrl,'?')===false)
// 			{
// 				//尝试断点续传
// 				$options[CURLOPT_RESUME_FROM] = $this->receivedLength;
// 			}

			curl_setopt_array($handle, $options);
			@curl_setopt($handle, CURLOPT_FOLLOWLOCATION, false);
			//@curl_setopt($handle, CURLOPT_MAXREDIRS, self::MAX_REDIRECTS);

			//发出请求（返回数据在writeHeader和writeBody这两个事件里处理）
			//根据响应头判断是否应该继续接收响应体，在writeHeader事件里实现了阻止操作
			$this->startTime=microtime(true);
			$ret = curl_exec($handle);

			//服务器端完成重定向
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
				//连接错误时重试
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

		//如果$finished=true时，表示已经接收完所有数据，
		//1. 如果不需要解压，writeBody里可能包含内容，需要把它返回给调用者
		//2. 如果需要解压，网页存在于writeBody里，并没把任何内容返回给调用者，需要解压后再返给调用者（没下载完整的不能解压）
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
 * 使用 fopen 函数实现http协议
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

		//设置脚本超时
		if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->connectTimeout+5);
		//连接
		$this->lastUrl = $this->url->url;
		if($this->logFileHandle){
			$this->addHttpLog("\n>>> HttpFopen：\n");
			$this->addHttpLog($context);
			$this->addHttpLog("\n\n");
		}
		$handle = fopen($this->url->url, 'r', false, $context);
		if (!$handle){
			$this->lastError = 'http request failed! Could not open handle for fopen() to the remote.';
			return false;
		}
		//设置与远端服务器之间的stream操作超时
		stream_set_timeout($handle, intval($this->readTimeout));
		if($this->shouldStop) return false;

		//设置脚本超时
		if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		//接收响应头
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

			//通知调用者收到HTTP头
			$this->onReceivedHeader($this->responseHeaders, false);
			if($this->shouldStop || $this->lastError){
				fclose($handle);
				return false;
			}

			//任何不含有消息体的消息（如1XX、204、304、50X等响应消息和任何头(HEAD，首部)请求的响应消息），总是由一个空行（CLRF）结束。
			if($this->requestMethod=='HEAD' || in_array($this->responseStatusCode, array(100,101,204,301,302,304)) || $meta['eof']){
				$this->onReceivedBody(null, true, false);
				fclose($handle);
				return true;
			}
		}

		if($this->lastError || $this->shouldStop) return false;
		@stream_context_set_params($context, array("notification" => null));

		//接收响应体
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

			//设置脚本超时
			if(ENABLE_SET_TIME_LIMIT) set_time_limit($this->readTimeout+5);
		}

		$finished = $finished || ($this->contentLength>0 && strlen($allContent)>=$this->contentLength) || feof($handle);
		$context=null;
		fclose($handle);
		$handle=null;
		if($this->shouldStop || connection_aborted()) return false;

		if($this->shouldUnzip){
			//被压缩的数据需要在完成时先进行解压，没完成时不能返回给调用者
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
 * 使用举例
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
	protected $ignore404=true; //当为true时，如果返回404状态，就不再接收内容了
	public $responseBody;
	public $contentLength;
	public $currentHome;
	public $connectTimeout = 5;
	public $readTimeout = 5;
	public $maxRetry = HTTP_MAX_RETRIES;
	public $isText=false;
	public $shouldUnzip=false;
	/**
	 * 下边两个回调函数的所属对象，如果为null，这两个函数就是普通函数，否则就是此对象的方法
	 */
	protected $sender = null;
	/**
	 * 完整返回HTTP头部之后的事件，参数：$http, $headers, $fromCache
	 */
	protected $receivedHeaderCallback = null;
	/**
	 * 返回每块儿HTTP主体时的事件，参数：$http, $data, $finished, $fromCache
	 */
	protected $receivedBodyCallback = null;
	//日志文件句柄
	protected $logFileHandle = null;

	/*
	 * 返回网页的content-type (不包含charset)
	 */
	public $contentType;
	/*
	 * 返回网页的charset
	*/
	public $charset;

	/**
	 * 是否自动转向
	 */
	public $redirect = true;
	/**
	 * 本地缓存目录（默认保存到 TEMPDIR 里，在计算缓存文件名时，将使用 $cacheDir、请求的网址、cacheSalt、cacheExt 组合计算而得）
	 */
	public $cacheDir = TEMPDIR;
	/**
	 * 被缓存对象的额外属性（在计算缓存文件名时，将使用 $cacheDir、请求的网址、cacheSalt、cacheExt 组合计算而得）
	 */
	public $cacheSalt = null;
	/**
	 * 本地缓存扩展名（在计算缓存文件名时，将使用 $cacheDir、请求的网址、cacheSalt、cacheExt 组合计算而得）
	 */
	public $cacheExt = null;
	/**
	 * 是否在实际发送HTTP请求之前先检查是否有可用的本地缓存，
	 * 至于得到实际的HTTP响应时是否写入缓存，则在调用者那里实现，不在本对象里实现
	 * 没有对缓存所占用的总磁盘空间进行检查，只有当磁盘剩余空间足够满足应用时才建议开启。
	 */
	public $readCache = false;
	/**
	 * 读取缓存时，如果缓存超过了此时间，就认为已经过期了
	 */
	public $cacheExpire = 0;
	/**
	 * 设置代理服务器，例如  127.0.0.1:8010
	 */
	public $proxy = null;
	/**
	 * 最近一次发生的错误
	 */
	public $lastError = null;

	//抽象方法 (派生类不要有自己的构造函数和析构函数，并且都要实现以下这几个方法)
	protected abstract function onCreate();
	protected abstract function onDestroy($force=false);
	protected abstract function doRequest();

	/**
	 * 根据服务器环境自动选择http协议的实现方式
	 * @param array $config 设置（可以包含：max_file_size, connect_timeout, read_timeout, proxy，没包含的项目将使用默认值）
	 * @return mixed 如果成功则返回当前服务器锁支持的http对象，如果失败就返回false
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

		//默认设置
		if(!isset($config['max_file_size'])) {
			$config['max_file_size']=10;
		}
		if(!isset($config['connect_timeout'])) $config['connect_timeout']=5;
		if(!isset($config['read_timeout'])) $config['read_timeout']=5;
		if(!isset($config['proxy'])) $config['proxy']='';
		if(!isset($config['enable_ssl'])) $config['enable_ssl']=extension_loaded('openssl');
		if(!isset($config['zlib_remote'])) $config['zlib_remote']=extension_loaded("zlib");

		//其他设置
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
	 * 在每次新的请求之前，都先初始化变量
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
	 * 停止
	 */
	public function stop(){
		$this->shouldStop = true;
		$this->closeHttpLog();
	}

	/**
	 * 强制关闭http
	 */
	public function close(){
		$this->onDestroy(true);
		$this->closeHttpLog();
	}

	/**
	 * 通知调用者收到了全部的HTTP头
	 * @param mixed $header 解析后的数组格式，或者未解析的原始字符串形式
	 * @param bool $fromCache 数据是否来源于缓存
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
			//检查无效的HTTP状态码
			if($this->responseStatusCode<=0){
				$this->lastError='timeout';
				return false;
			}
			//判断文件大小是否超出
			if ($this->requestMethod!='HEAD' &&
				$this->contentLength>0 && $this->config['max_file_size'] && $this->contentLength>$this->config['max_file_size']*1024*1024 &&
				strpos($this->getResponseHeader('Content-Type',''), 'video/')===false) {
				$this->lastError='resource';
				return false;
			}
			//错误的状态码
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
	 * 通知调用者收到了部分HTTP内容
	 * @param string $data
	 * @param bool $finished 内容是否到达结尾
	 * @param bool $fromCache 数据是否来源于缓存
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
	 * 打开调试日志
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
	 * 测试是否支持SSL
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
	 * HEAD 请求 （从不使用缓存）
	 * @param string $url
	 * @param array $headers(可选) 如果不为空将与现有请求头合并并覆盖已有的设置
	 * @return array 返回解析后的数组，如果失败就返回false
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
	 * GET 请求 （设置了$cacheDir、设置了$readCache、并且cookie为空时会先检查缓存）
	 * @param string $url
	 * @param array $headers(可选) 如果不为空将与现有请求头合并并覆盖已有的设置
	 * @param object $sender 调用本函数的对象，如果为null，后边两个函数就是普通函数，否则就是此对象的方法
	 * @param function onReceivedHeader 当收到完整的header时执行此函数，参数为：$http, $header
	 * @param function onReceivedBody 当收到每块儿body时执行此函数，参数为：$http, $data, $finished
	 * @return bool 成功就返回true，失败返回false
	 * 无论是否指定了onReceivedHeader，响应头都会保存到$responseHeaders里，
	 * 如果指定了onReceivedBody，响应体在此事件里处理，否则就保存到$responseBody里
	 */
	public function get($url, $requestHeaders=null, $sender=null, $onReceivedHeader=null, $onReceivedBody=null){
		$this->requestMethod = 'GET';
		if(!$url){
			$this->lastError = 'url不能为空';
			return false;
		}
		$this->url = is_object($url)?$url:Url::create($url);
		if(!$this->url){
			$this->lastError = 'url格式有误';
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
	 * POST 请求 （设置了$cacheDir、设置了$readCache、cookie为空、并且没有要提交的数据时会先检查缓存）
	 * @param string $url
	 * @param mixed $data 要提交的表单数据，如果是字符串将不进行编码直接提交，如果是数组将先与现有的值合并并覆盖已有的值然后再进行编码
	 * @param array $headers(可选) 如果不为空将与现有请求头合并并覆盖已有的设置
	 * @param object $sender 调用本函数的对象，如果为null，后边两个函数就是普通函数，否则就是此对象的方法
	 * @param function onReceivedHeader 当收到完整的header时执行此函数，参数为：$http, $header
	 * @param function onReceivedBody 当收到每块儿body时执行此函数，参数为：$http, $data, $finished
	 * @return mixed 成功就返回响应体，失败返回false
	 */
	public function post($url, $data=null, $requestHeaders=null, $sender=null, $onReceivedHeader=null, $onReceivedBody=null){
	    $this->requestMethod = 'POST';
		$this->url = is_object($url)?$url:Url::create($url);
		if(!$this->check()) return false;
		$this->addRequestHeaders($requestHeaders);
		if($data){
			if(!is_array($data)){
				if(!empty($this->postFields) || !empty($this->postFiles)){
					$this->lastError = '已经设置了提交数据，不能在post方法里再指定字符串形式的提交数据了！';
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
	 * 判断当前HTTP请求是否应该使用缓存
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
	 * 检查缓存是否有变化，如果服务器返回304就表示没有变化，比较依据为了简单化只采用了修改时间
	 * @param CacheHttp $cache
	 * @return bool 如果可能有变化就返回true，没变化就返回false
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
				//获取远程服务器上文件的修改时间，需要消去远端服务器与本服务器的时间误差，或者假设最大误差为10分钟
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
	 * 显示缓存里的内容，输出方式也使用事件方式
	 * 因为缓存里的内容可能是处理过的，HTTP返回的内容还需要额外处理，所以为了区分，在事件里有个标志表示是否是来源于缓存
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
	 * 下载指定网页的源代码
	 * @param string $url 网址
	 * @param string $useragent
	 * @param array $config 设置（可以包含：max_file_size, connect_timeout, read_timeout, proxy，没包含的项目将使用默认值）
	 * @return mixed 如果网址下载失败就返回false，否则就返回HTTP头部内容
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
	 * 下载指定网页的源代码(处理一次转向，但是并没有自动处理上一步返回的set-cookie)
	 * @param string $url 网址
	 * @param string $useragent
	 * @param string $charset 返回内容的编码（原始网页会自动转换为此编码）
	 * @param boolean $returnHeader 是否返回http响应头
	 * @param array $config 设置（可以包含：max_file_size, connect_timeout, read_timeout, proxy, charset，没包含的项目将使用默认值）
	 * @return string 如果网址下载失败就返回false，否则就返回转换编码后的内容
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
	 * 提交表单，返回网页源代码
	 * @param string $url 网址
	 * @param string $data 要提交的数据
	 * @param string $useragent
	 * @param string $charset 返回内容的编码（原始网页会自动转换为此编码）
	 * @param boolean $returnHeader 是否返回http响应头
	 * @param array $config 设置（可以包含：max_file_size, connect_timeout, read_timeout, proxy，没包含的项目将使用默认值）
	 * @return string 如果网址下载失败就返回false，否则就返回转换编码后的内容
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
	 * 从网页内容里提取charset
	 * @param string $content 网页内容
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
	 * 最终访问的url
	 */
	public function getLastUrl(){
		return $this->lastUrl;
	}

	/**
	 * 检查是否已经设置了某个HTTP请求头
	 */
	public function checkRequestHeader($key){
		$key = strtolower($key);
		if(!$key) return false;
		return isset($this->requestHeaders[$key]);
	}

	/**
	 * 设置一个HTTP请求头
	 * @param $key string 名称
	 * @param $value string 如果为空将删除此字段
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
	 * 追加header数组到HTTP请求头
	 * @param array $headers
	 */
	private function addRequestHeaders($headers){
		if(!is_array($headers) || empty($headers)) return;
		foreach($headers as $k=>$v){
			$this->setRequestHeader($k, $v);
		}
	}

	/**
	 * 读取HTTP请求头的值
	 * @param $key string 要读取的名称，如果为空将返回所有HTTP请求头数组
	 * @return mixed 字符串（如果请求值不存在将返回null）或者数组
	 */
	public function getRequestHeader($key=null) {
		$key = strtolower($key);
		if(!$key)
			return $this->requestHeaders;
		else
			return isset($this->requestHeaders[$key]) ? $this->requestHeaders[$key] : null;
	}

	/**
	 * 设置域名验证信息（Authorization头）
	 * $value string 如果为空，将删除已经添加的Authorization头
	 */
	public function setAuth($value){
		if($value && stripos($value, 'Basic ')!==0){
			$value = 'Basic '.$value;
		}
		$this->setRequestHeader('Authorization', $value);
	}

	/**
	 * 添加一个cookie值到请求头里
	 */
	public function setCookie($key, $value) {
		if(!$key) return;
		$this->requestHeaders['cookie'][$key] = $value;
	}

	/**
	 * 添加cookie列表到请求头里
	 */
	public function setCookies($cookies) {
		foreach($cookies as $k=>$v){
			$this->requestHeaders['cookie'][$k] = $v;
		}
	}

	/**
	 * 从HTTP请求头里读取一个cookie
	 * @param $key string 要读取的名称，如果为空将返回所有cookie数组
	 * @return mixed 字符串（如果请求值不存在将返回null）或者数组
	 */
	public function getCookie($key=null) {
		// fetch from last request
		if (!$key)
			return $this->requestHeaders['cookie'];
		else
			return isset($this->requestHeaders['cookie'][$key]) ? $this->requestHeaders['cookie'][$key] : null ;
	}

	/**
	 * 从服务器返回的set-cookie记录里提取需要在下次请求时发送的cookie
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
	 * 把请求头数组转换为适用于http请求头的字符串
	 * param bool $includeMethodAndHost 是否返回前两行（method和host）
	 * param string $returnType 可选值包含： 'string' 或 'array'
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
	 * 添加某一个要提交的值
	 * @param $key string 表单名称
	 * @param mixed 字符串或数组，如果是数组将会被自动转换为 arr[key][key2]
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
	 * 添加一个要提交的文件
	 * @param string $key 表单变量名称
	 * @param string $filename 要提交的文件名
	 * @param string 如果为空并且$filename是一个真实的文件，将自动从$filename里载入
	 */
	public function addPostFile($key, $filename, $content=null) {
		if(!$key) return;
		if (!$content && is_file($filename))
			$content = file_get_contents($filename);
		$this->postFiles[$key] = array(basename($filename),	$content);
	}

	/**
	 * 设置要提交的文本
	 */
	public function setPostData($data){
		$this->postData = $data;
	}

	/**
	 * 组合要提交的数据
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
	 * 最后一次HTTP相应头
	 */
	public function getResponseHeadersText() {
		return $this->responseHeadersText;
	}

	/**
	 * 最后一次HTTP请求的状态行
	 */
	public function getResponseStatusText() {
		return $this->responseStatusText;
	}

	/**
	 * 最后一次HTTP请求的状态值
	 */
	public function getResponseStatusCode() {
		return $this->responseStatusCode;
	}

	/**
	 * 解析服务器返回的HTTP状态值，解析结果保存在 $responseStatus字段里
	 * @param string $str
	 * @return int 成功就返回$responseStatusCode，失败返回false
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
	 * 解析服务器返回的HTTP头，解析结果保存在 $responseHeaders 字段里
	 * @param string $str
	 * @return array 成功就返回$responseHeaders，失败返回false
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
					//从响应头里提取contentType和charset
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
	 * 从响应头里提取文件名
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
	 * dns解析并缓存到文件
	 * @param $host string 域名
	 * @param $force bool 是否强制执行解析（否则就先检查有效期内的缓存）
	 * @param string 成功则返回ip，失败则返回host
	 */
	protected function resolve($host, $force=false) {
		//解析超时问题未解决，不再提前解析
		return $host;


		if(preg_match('/^\d+\.\d+\.\d+\.\d+$/', $host)) {
			return $host;
		}

		if($host=='localhost') {
		    return '127.0.0.1';
		}

		$ip = null;
		if ($this->cacheDir) {
			//读取缓存
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

		//从新解析
		$ip = @gethostbyname($host);
		if ($ip != $host) {
			array_unshift($ips, "{$host}/" . date('g') . "/{$ip}\n");
			file_put_contents($this->cacheDir.'/dns.~tmp', implode('',$ips), LOCK_EX);
		}
		return $ip;
	}

	//解压
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
	 * 是不是蜘蛛
	 * @return mixed 如果不是蜘蛛就返回false，如果是蜘蛛就返回蜘蛛的名称或分组
	 */
	public static function isSpider()
	{
		static $is_spider=null;
		if($is_spider===null) {
			$is_spider=false;
			if (empty($_SERVER['HTTP_USER_AGENT'])){
				$is_spider=false;
			}else{
				//搜索引擎蜘蛛特征列表，前边是特征，后边是搜索引擎名称。当蜘蛛访问页面时页面内容不进行编码
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
	 * 是不是蜘蛛（更简洁的判断方式）
	 * @return boolean
	 */
	public static function isSpider2()
	{
		return preg_match('#(google|spider|bot|slurp|crawler)\W#i', $_SERVER['HTTP_USER_AGENT']);
	}

	/**
	 * 判断是否是通过手机访问
	 * @return bool 是否是移动设备
	 */
	public static function isMobile() {
		static $is_mobile=null;
		if($is_mobile===null) {
			$is_mobile=false;
			// 如果有HTTP_X_WAP_PROFILE则一定是移动设备
			if (isset($_SERVER['HTTP_X_WAP_PROFILE']) && $_SERVER['HTTP_X_WAP_PROFILE']) {
				$is_mobile=true;
			}
			//如果via信息含有wap则一定是移动设备,部分服务商会屏蔽该信息
			elseif (isset($_SERVER['HTTP_VIA']) && stristr($_SERVER['HTTP_VIA'], "wap")!==false) {
				$is_mobile=true;
			}
			//脑残法，判断手机发送的客户端标志,兼容性有待提高
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
			//协议法，因为有可能不准确，放到最后判断
			elseif(isset($_SERVER['HTTP_ACCEPT']) && ($s=strtolower($_SERVER['HTTP_ACCEPT']))) {
				// 如果只支持wml并且不支持html那一定是移动设备
				// 如果支持wml和html但是wml在html之前则是移动设备
				if (($x=strpos($s, 'vnd.wap.wml')) !== false && (($y=strpos($s, 'text/html')) === false || $x>$y)) {
					$is_mobile=true;
				}
			}
		}
		return $is_mobile;
	}

	/**
	 * 获取HTTP请求原文
	 * @return string
	 */
	public static function getRawRequest() {
		$raw = '';
		// (1) 请求行
		$raw .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
		// (2) 请求Headers
		foreach($_SERVER as $key => $value) {
			if(substr($key, 0, 5) === 'HTTP_' && !empty($value)) {
				$key = substr($key, 5);
				$key = strtr($key, '_', ' ');
				$key = ucwords(strtolower($key));
				$key = strtr($key, ' ', '-');
				$raw .= $key.': '.$value."\r\n";
			}
		}
		// (3) 空行
		$raw .= "\r\n";
		// (4) 请求Body
		$raw .= file_get_contents('php://input');
		return $raw;
	}
}



