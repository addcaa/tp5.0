<?php
/**
 * 商城下单相关接口基础控制器
 */
namespace app\common\controller;

use think\Controller;
use think\Db;

class ApibaseController extends Controller
{
	/**
	 * 初始化
	 */
	public function __construct() {
	    parent::__construct();
	    if(!$this->request->isPost()){
	        exit('非法请求');
	    }
	    $this->secret_key = config('ruuby.secret_key');
	}
	// 获取签名
	public function get_sign($params,$secret){
		if(empty($params) || !is_array($params)){
			return false;
		}
		// 获取签名字串
		$sign_str = $this->get_sign_content($params);
		$sign_str = $secret.$sign_str.$secret;
		$sign = strtoupper(md5($sign_str));
		return $sign;
	}

	/*签名排序*/    
	public function get_sign_content($params) {
	    ksort ( $params );
	    unset($params['sign']);
	    $stringToBeSigned = "";
	    foreach ( $params as $k => $v ) {
	    	if(!is_array($v)){
				if (false === $this->check_empty ( $v ) && "@" != substr ( $v, 0, 1 )) {
		            $stringToBeSigned .= "$k" . "$v";
		        }
	    	}
	        
	    }
	    unset ( $k, $v );
	    return $stringToBeSigned;
	}



	/*校验$value是否非空*/
	public function check_empty($value) {
	    if (! isset ( $value ))
	        return true;
	    if ($value === null)
	        return true;
	    if (trim ( $value ) === "")
	        return true;
	    return false;
	}
}