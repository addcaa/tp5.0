<?php
/**
 * 自定义基础控制器.
 */

namespace app\common\controller;

use think\Controller;
use think\Db;

// use system\Auth;
class BaseController extends Controller
{
    /**
     * 初始化.
     */
    public function __construct()
    {
        parent::__construct();

        $this->userAuth();

    }

    public function userAuth(){
        $data="data";
        $this->assign('data',$data);
    }
}
