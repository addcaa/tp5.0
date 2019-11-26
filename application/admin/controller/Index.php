<?php

namespace app\admin\controller;

use app\common\controller\BaseController;
use think\Controller;
class Index extends BaseController {

    public function index(){
        return $this->fetch();
    }

    public function add(){
        return $this->fetch();

    }
}
