<?php
/**
 * 自定义基础控制器.
 */

namespace app\common\controller;

use SensitiveWordTree;
use think\Controller;
use think\Db;
use think\Request;
// 加密类
use encrypt\aes256cbc\Aes;
use encrypt\rsa256\Rsa;
use think\Session;
use Qiniu\Auth;
use Qiniu\Storage\UploadManager;


include APP_PATH.'../extend/system/auth.php';
// use system\Auth;
class BaseController extends Controller
{
    /**
     * 顶部菜单.
     */
    protected $top_menu = [];

    /**
     * 初始化.
     */
    public function __construct()
    {
        parent::__construct();

        // 检查是否登录

        $this->checkLogin();


        // 获取用户权限信息
        $this->userAuth();

        $this->conf = config('ekey_certs');
        $data_arr = ['pingt' => '[]', 'huod' => '[]', 'shangj' => '[]', 'shangp' => '[]'];

        $this->assign('data_arr', $data_arr);

    }

    /**
     * 【FUNCTION】检查是否登录.
     */
    protected function checkLogin()
    {
        if (defined('UID')) {
            return;
        }

        define('UID', is_login());

        if (!UID) {
            $this->redirect('/system/public/login');
        }
    }

    /**
     * 【FUNCTION】检查是否登录.
     */
    protected function checkLogin_new()
    {
        if (defined('UID')) {
            return;
        }

        define('UID', is_login());

        if (!UID) {
            if (!empty(Session::get('is_login'))) {
                return true;
            }
            Session::set('is_login', 0);
            $seid = base64_encode(session_id().','.microtime(true));
            $back_url = config('login_url.host_url');
            $req_url = config('login_url.auth_url');
            $appid = config('login_url.appid');
            $redirect_uri = urlencode($back_url.'system/public/callback');

            $authurl = $req_url."auth/authorize?appid={$appid}&redirect_uri={$redirect_uri}&se={$seid}";

            return $this->redirect($authurl);
        }
    }

    /**
     * 【FUNCTION】获取用户权限信息.
     */
    protected function userAuth()
    {
        $url = '/url/1';
        $this->assign('url', $url);

        $request = Request::instance();

        $groupid = Db::name('platform_auth_group_access')->where('uid = '.UID)->find();
        
        $authGroup = Db::name('platform_auth_group')->where('id', $groupid['group_id'])->find();

        if (empty($authGroup['rules'])) {
            p('您没有权限，请联系管理员', 1);
        }
        // P($authGroup);exit;
        // 获取部门
        // $branch_name = Db::name('platform_branch')->where('id', $authGroup['branch_id'])->value('name');
        $child = Db::name('platform_auth_rule')->where('id IN ('.$authGroup['rules'].') AND status = 0 AND is_child = 1')
            ->order('order', 'desc')->field('id,name,title,pid')->select();
        $modules = Db::name('platform_auth_model')
            ->where('id', 'IN', $authGroup['auth_model_id'])
            ->where('status', 0)
            ->order('order', 'desc')
            ->select();

        $menu = [];
        foreach ($modules as $key => $val) {
            $menu[$key]['mid'] = $val['id'];
            $menu[$key]['title'] = $val['title'];
            $menu[$key]['code'] = $val['code'];
            $menu[$key]['icon'] = $val['icon'];
            foreach ($child as $keyc => $valc) {
                if ($valc['pid'] == $val['id']) {
                    $action = explode('/', $valc['name']);
                    $valc['module_name'] = $action[0];
                    $valc['controller_name'] = isset($action[1]) ? $action[1] : 'index';
                    $valc['action_name'] = isset($action[2]) ? $action[2] : 'index';
                    $menu[$key]['child'][] = $valc;
                }
            }
        }
        /*
         * @desc用于后台菜单的高亮显示
         * 获取当前的URL确定 访问的模块名称和控制器名称(这里的名称和权限表中的节点位置是一样的)
         * 不用 $this->request->controller() 是它的结果有时和url和节点位置中的名称不一样
         * 如节点位置：system/auth_group/index 获取结果：AuthGroup
         */
        $baseurl = explode('/', trim(strtolower($this->request->baseUrl()), '/'));
        /*
         *  获取当前路径的父级ID
         */
//        $pid = 0;
//        foreach ($child as $keyc => $valc) {
//            if (trim($this->request->baseUrl(), '/') == $valc['name']) {
//                $pid = $valc['pid'];
//            }
//        }

        $curenturl = $this->getActionUrl(3);
        $curentrule = Db::name('platform_auth_rule')->field('id,pid,cid')->where('name',$curenturl)->find();

        if(!empty($curentrule)){
            if($curentrule['cid'] == 0){
                $curentrule['cid'] = $curentrule['id'];
                $curentrule['pid'] = $curentrule['pid'];
            }
        }else{
            $curentrule['cid'] = 0;
            $curentrule['pid'] = 0;
        }

        $this->assign([
            'menu' => $menu, //菜单
            'request_module_name' => !empty($baseurl[0]) ? $baseurl[0] : strtolower(config('default_module')), //当前模块
            'request_controller_name' => !empty($baseurl[1]) ? str_replace('.'.config('default_return_type'), '', $baseurl[1]) : strtolower(config('default_controller')), //当前控制器
            'request_action_name' => !empty($baseurl[2]) ? str_replace('.'.config('default_return_type'), '', $baseurl[2]) : strtolower(config('default_action')), //当前方法
            // 'branch_name' => $branch_name,

            'curentpid' => $curentrule['pid'],
            'curentcid' => $curentrule['cid'],

            'role_name' => $authGroup['title'],
            // 'user' => $this->get_user_info(session('user_auth.uid')),
            'user' => session('user_auth'),
        ]);
        //获取当前Url此地方写成函数是为了方便多地方调用

        $Action_Url = $this->getActionUrl(3);
        $this->assign('request', $request);

        // //权限检测
        $auth = new \Auth();
        if (!$auth->check($Action_Url, UID)) {
            if ($this->request->isAjax()) {
                return_json(['code' => '99', 'msg' => '没有权限！', 'data' => '']);
            } else {
                $this->error('没有权限！', null, '', 1);
            }
        }

    }

    /**
     * 【FUNCTION】获取当前URL.
     */
    protected function getActionUrl($true = 0)
    {
        $request = Request::instance();
        switch ($true) {
            case 1:
                return url($request->module().'/'.$request->controller().'/'.$request->action());
                break;
            case 2:
                return $request->module().'/'.$request->controller().'/'.$request->action();
                break;
            case 3:
                $baseurl = explode('/', trim(strtolower($this->request->baseUrl()), '/'));
                $m = !empty($baseurl[0]) ? $baseurl[0] : config('default_module');
                $c = !empty($baseurl[1]) ? $baseurl[1] : config('default_controller');
                $a = !empty($baseurl[2]) ? $baseurl[2] : config('default_action');
                $u = $m.'/'.$c.'/'.$a;

                return str_replace('.'.config('default_return_type'), '', $u);
                break;
            default:
                return $request->module().'/'.$request->controller().'/'.$request->action();
                break;
        }
    }

    /**
     * RSA加密.
     *
     * @param [type] $data [原始字符串]
     *
     * @return [type] [密文字符串]
     */
    public function rsa_encrypt_data($data)
    {
        $this->conf = config('ekey_certs');
        $rsa = new Rsa($this->conf);
        $res = $rsa->publicKeyEncode($data);

        return $res;
    }

    /**
     * RSA解密.
     *
     * @param [type] $data [密文字符串]
     *
     * @return [type] [原始字符串]
     */
    public function rsa_decrypt_data($data)
    {
        $rsa = new Rsa($this->conf);
        $res = $rsa->decodePublicEncode($data);

        return $res;
    }

    /*
     * 上传图片
     * @param $file 文件流
     * @param $upload_path 保存路径
     */
    public function upload_img($file, $upload_path = '')
    {
        if (empty($upload_path)) {
            $upload_path = ROOT_PATH.'public'.DS.'static'.DS.'uploads'.DS;
        }

        $size = config('upload.img_size');
        $ext = config('upload.img_ext');
        $info = $file->validate(['size' => $size, 'ext' => $ext])->rule('uniqid')->move($upload_path);
        if ($info) {
            return array(
                'code' => '0',
                'save_name' => $info->getSaveName(),
            );
        } else {
            return array(
                'code' => '1',
                'error' => $file->getError(),
            );
        }
    }

    // 管理员列表
    public function get_user_list($where = '')
    {
        $auth_url = config('auth_url').'user_list';
        // $auth_url = 'safe.hxfybj.net.local/api/user_list';
        $json = http_curl($auth_url, array('where' => serialize($where)), 'POST');
        $res = json_decode($json, true);
        if ($res['code'] != 0) {
            $this->error($res['msg'], null, '', 1);
        }

        return $res['data'];
    }

    // 获取管理员信息
    public function get_user_info($uid = 0)
    {
        $where = [];
        $where['uid'] = $uid;
        $data = Db::name('admin_user')->where($where)->find();

        if (empty($data)) {
            $this->error($res['msg'], null, '', 1);
        }
        return $data;


        //
        $post_data['data'] = $this->rsa_encrypt_data($uid);
        $auth_url = config('auth_url').'get_user_info';
        // $auth_url = 'safe.hxfybj.net.local/api/get_user_info';
        $json = http_curl($auth_url, $post_data, 'POST');
        $res = json_decode($json, true);
        if ($res['code'] != 0) {
            $this->error($res['msg'], null, '', 1);
        }

        return $res['data'];
    }

    // 保存管理员信息
    public function save_user_info($uid = 0, $name = '', $mobile = '', $status = 0, $email = '')
    {
        $string = $uid.','.$name.','.$mobile.','.$status.','.$email;
        $post_data['data'] = $this->rsa_encrypt_data($string);
        $auth_url = config('auth_url').'save_user_info';
        // $auth_url = 'safe.hxfybj.net.local/api/save_user_info';
        $json = http_curl($auth_url, $post_data, 'POST');
        $res = json_decode($json, true);
        if ($res['code'] != 0) {
            $this->error($res['msg'], null, '', 1);
        }

        return $res['data'];
    }

    /**
     * 导出.
     */
    public function exportExcel($fileName, $headArr, $data, $type = '')
    {
        ob_end_clean();
        import('PHPExcel', EXTEND_PATH);
        import('PHPExcel.Writer.CSV', EXTEND_PATH);
        import('PHPExcel.Writer.Excel5', EXTEND_PATH);
        import('PHPExcel.IOFactory', EXTEND_PATH);
        import('PHPExcel.Cell.DataType', EXTEND_PATH);
        if (empty($data) || !is_array($data)) {
            return $this->error('导出失败，数据为空',null,'',1);
        }
        if (empty($fileName)) {
            exit;
        }
        $date = date('Y_m_d', time());
        $fileName .= "_{$date}.xlsx";
        //创建新的PHPExcel对象
        $objPHPExcel = new \PHPExcel();
        $objDataType = new \PHPExcel_Cell_DataType();
        $objProps = $objPHPExcel->getProperties();
        //设置表头
        $kk = ord('A');
        //r_dump($headArr);
        foreach ($headArr as $v) {
            $colum = chr($kk);
            $objPHPExcel->setActiveSheetIndex(0)->setCellValue($colum.'1', $v);
            ++$kk;
        }

        $column = 2;
        $objActSheet = $objPHPExcel->getActiveSheet();
        foreach ($data as $key => $rows) { //行写入
            $span = ord('A');
            foreach ($rows as $keyName => $value) {// 列写入
                $j = chr($span);
                $objActSheet->setCellValue($j.$column, $value);
                ++$span;
            }
            if ($type == 'COUPON') {
                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['num'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['pass'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('D'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'DANGDANG') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['number'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'CMTJ') {
                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['mobile'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['id_code'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('D'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'MOTHERDAY') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_code'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'SENDGOODS') {
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['orderno'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('K'.($key + 2), $rows['rece_phone'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('K'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }

            if ($type == 'KRBB') {
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['mobile'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'COUPONS') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['number'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['password'], $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('D'.($key + 2), date('Y-m-d H:i:s', $rows['expired']), $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('E'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'BOC') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_id'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['number'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('D'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('E'.($key + 2), $rows['coupon_pwd'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('E'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'AQY') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('C'.($key + 2), date('Y-m-d H:i:s', $rows['add_time']), $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'XZY') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_no'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['phone'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), date('Y-m-d H:i:s', $rows['add_time']), $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('D'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('E'.($key + 2), $rows['amount'] / 100, $objDataType::TYPE_STRING2);
            }
            if ($type == 'TM') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_no'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['price'] / 100, $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['nick'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['add_time'], $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('E'.($key + 2), trim($rows['model'], '"'), $objDataType::TYPE_STRING2);
            }
            if ($type == 'LT') {
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['send_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('C'.($key + 2), date('Y-m-d H:i:s', $rows['add_time']), $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['amount'], $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('E'.($key + 2), $rows['phone'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('E'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('G'.($key + 2), $rows['coupon_status'], $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('H'.($key + 2), $rows['remind'], $objDataType::TYPE_STRING2);
            }
            if ($type == 'YCH') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_no'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');

                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['phone'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');

                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['add_time'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('D'.($key + 2))->getNumberFormat()->setFormatCode('@');

                $objActSheet->setCellValueExplicit('E'.($key + 2), $rows['delivery_time'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('E'.($key + 2))->getNumberFormat()->setFormatCode('@');

                $objActSheet->setCellValueExplicit('G'.($key + 2), $rows['courier_no'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('G'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'SNCP') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['inTradeNo'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'YQB') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['phone'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('H'.($key + 2), $rows['add_time'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('H'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'YQBORDER') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['sub_order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['jd_order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['jd_sub_order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('D'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'YQBAFTER') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['sub_order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('B'.($key + 2))->getNumberFormat()->setFormatCode('@');
            }
            if ($type == 'XTK') {
                $objActSheet->setCellValueExplicit('A'.($key + 2), $rows['order_sn'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('A'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['price'] / 100, $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('C'.($key + 2), $rows['account'], $objDataType::TYPE_STRING2);
                $objActSheet->getStyle('C'.($key + 2))->getNumberFormat()->setFormatCode('@');
                $objActSheet->setCellValueExplicit('D'.($key + 2), $rows['add_time'], $objDataType::TYPE_STRING2);
            }
            if ($type == 'SH') {
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['after_sales_no'], $objDataType::TYPE_STRING2);
                $objActSheet->setCellValueExplicit('B'.($key + 2), $rows['orderno'], $objDataType::TYPE_STRING2);
            }
            ++$column;
        }
        //$fileName = iconv("UTF-8", "GBK", $fileName);
        //设置活动单指数到第一个表,所以Excel打开这是第一个 表
        $objPHPExcel->setActiveSheetIndex(0);
        header('Content-Type: application/vnd.ms-excel');
        header("Content-Disposition: attachment;filename=\"$fileName\"");
        header('Cache-Control: max-age=0');
        $objWriter = \PHPExcel_IOFactory::createWriter($objPHPExcel, 'Excel2007');
        $objWriter->save('php://output'); //文件通过浏览器下载
        exit;
    }

    // // 验证系统管理员密码
    // public function verify_admin_pass($pass = '')
    // {
    //     $auth_url = config('auth_url').'safe_auth';
    //     $string = '2'.','.time().','.$pass;
    //     $post_data['data'] = $this->rsa_encrypt_data($string);
    //     $json = http_curl($auth_url, $post_data, 'POST');
    //     $res = json_decode($json, true);
    //     if ($res['code'] == 0) {
    //         return true;
    //     } else {
    //         return false;
    //     }
    // }

    //获取商户简称方法
    public function get_merchant()
    {
        return $merchant = Db::name('merchant')->where('status', 0)->field('mid,simple_name')->select();
    }

    // 根据卡号获取券码
    public function get_coupon_by_number($number = '', $ide_code = '', $coupon_source = '')
    {
        $url = config('coupon').'/api/get_coupon_info_by_number';
        $send_data['number'] = $number;
        $send_data['ide_code'] = $ide_code;
        $send_data['coupon_source'] = $coupon_source;
        $res = http_curl($url, $send_data, 'POST');
        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return $send_res['data'];
        } else {
            return false;
        }
    }

    // 根据卡密获取券码
    public function get_coupon_by_password($password = '')
    {
        $url = config('coupon.coupon').'/api/get_coupon_info_by_password';
        $send_data['password'] = $password;

        $res = curl_no_error($url, $send_data, 'POST');
        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return $send_res['data'];
        } else {
            return false;
        }
    }

    //根据卡密获取sn
    public function get_coupon_info($password = '')
    {
        $send_data['type'] = 3;
        $send_data['password'] = $password;

        $url = config('coupon_url.get_coupon_info');
        $res = curl_no_error($url, $send_data, 'POST');

        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return $send_res['data'];
        } else {
            return false;
        }
    }

    /**
     * 获取券码信息
     * 使用自行添加 case.
     */
    public function getCouponInfo($info)
    {
        if (empty($info['type'])) {
            return false;
        }

        switch ($info['type']) {
            case 1:
                $send_data['type'] = 1;
                $send_data['sn'] = $info['sn'];
                break;
            case 2:
                $send_data['type'] = 2;
                $send_data['number'] = $info['number'];
                $send_data['pid'] = $info['pid'];
                $send_data['channel'] = $info['channel'];
                break;
            case 3:
                $send_data['type'] = 3;
                $send_data['password'] = $info['password'];
                break;
            default:
                return false;
                break;
        }

        $url = config('coupon_url.get_coupon_info');
        $res = curl_no_error($url, $send_data, 'POST');

        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return $send_res['data'];
        } else {
            return false;
        }
    }

    /**
     * 更新券码信息.
     */
    public function setCouponInfo($info)
    {
        if (empty($info['type'])) {
            return false;
        }

        switch ($info['type']) {
            case 1:
                $send_data['type'] = 1;
                $send_data['sn'] = $info['sn'];
                $send_data['pid'] = $info['pid'];
                $send_data['status'] = $info['status'];
                break;
            case 2:
                $send_data['type'] = 2;
                $send_data['sn'] = $info['sn'];
                $send_data['pid'] = $info['pid'];
                $send_data['expired'] = $info['expired'];
                break;
            default:
                return false;
                break;
        }

        $url = config('coupon_url.set_coupon_info');
        $res = curl_no_error($url, $send_data, 'POST');

        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return $send_res['data'];
        } else {
            return false;
        }
    }

    /**
     * 查询电子券[CID].
     */
    protected function getCouponInfoByCid($info)
    {
        $curlData['cid'] = $info['cid'];
        $curlData['coupon_source'] = $info['coupon_source'];

        $url = config('coupon.coupon').'/api/get_coupon_info_by_cid';

        $rsCoupon = curl_no_error($url, $curlData, 'POST');
        $reArr = json_decode($rsCoupon, true);

        return $reArr;
    }

    /**
     * 更新券码状态
     */
    protected function update_coupon_status($cid, $status, $coupon_source)
    {
        $send_data['cid'] = $cid;
        $send_data['status'] = $status;
        $send_data['coupon_source'] = $coupon_source;
        $url = config('coupon.update_coupon_status_url');
        $res = curl_no_error($url, $send_data, 'POST');
        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 更新券码状态V3.0.
     */
    protected function update_coupon_status_v3($sn, $pid, $status)
    {
        $send_data['type'] = 1;
        $send_data['sn'] = $sn;
        $send_data['pid'] = $pid;
        $send_data['status'] = $status;
        $url = config('coupon.set_coupon_info_url');
        $res = curl_no_error($url, $send_data, 'POST');
        $send_res = json_decode($res, true);
        if ($send_res['code'] == 0) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 查询电子券[CID].
     */
    protected function getCouponStock($info)
    {
        $curlData['pids'] = $info['pids'];
        $curlData['coupon_source'] = $info['coupon_source'];
        if (!empty($info['channel'])) {
            $curlData['channel'] = $info['channel'];
        }

        $url = config('coupon.coupon').'/stock/get_coupon_stock';

        $rsCoupon = curl_no_error($url, $curlData, 'POST');
        $reArr = json_decode($rsCoupon, true);

        return $reArr;
    }

    /**
     * RSA加密.
     *
     * @param [type] $data [原始字符串]
     *
     * @return [type] [密文字符串]
     */
    protected function rsa_encrypt_string($conf, $data)
    {
        $rsa = new Rsa($conf);
        $res = $rsa->publicKeyEncode($data);

        return $res;
    }

    /**
     * RSA解密.
     *
     * @param [type] $data [密文字符串]
     *
     * @return [type] [原始字符串]
     */
    protected function rsa_decrypt_string($conf, $data)
    {
        $rsa = new Rsa($conf);
        $res = $rsa->decodePublicEncode($data);

        return $res;
    }

    /**
     * 生成公钥私钥.
     */
    // public function make_ekey()
    // {
    //     // 生成Ekey ID
    //     $ekey_id = $this->randOnePass([1, 3], 32);

    //     $private_command = 'openssl genrsa -out '.ROOT_PATH.'certs/private_'.$ekey_id.'.pem 2048';
    //     $public_command = 'openssl rsa -in '.ROOT_PATH.'certs/private_'.$ekey_id.'.pem -pubout -out '.ROOT_PATH.'certs/public_'.$ekey_id.'.pem';

    //     system($private_command, $private_res);
    //     system($public_command, $public_res);

    //     if (($private_res === 0) && ($public_res === 0)) {
    //         $keys = $this->randOnePass([1, 2, 3, 4], 32);
    //         $conf = ['public_key_path' => ROOT_PATH.'certs/public_'.$ekey_id.'.pem', 'private_key_path' => ROOT_PATH.'certs/private_'.$ekey_id.'.pem'];
    //         $en_keys = $this->rsa_encrypt_string($conf, $keys);
    //         $data['rsa'] = $ekey_id;
    //         $data['aes'] = $en_keys;

    //         return $data;
    //     } else {
    //         return [];
    //     }
    // }

    /**
     * 生成单个卡密.
     *
     * @param array $item   [生成类型组合]
     * @param int   $length [密码长度]
     *
     * @return [string] [密码]
     */
    protected function randOnePass($item = [1, 2, 3, 4], $length = 18)
    {
        // 构成元素
        $chars = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '!@#$%^&*'];
        $str = '';
        foreach ($item as $key => $val) {
            $str .= $chars[$val - 1];
        }
        $code = $this->make_str($str, $length);

        return $code;
    }

    /**
     * 随机生成单个字符串.
     *
     * @param string $chars  [生成元素集合]
     * @param int    $length [密码长度]
     *
     * @return [string] [密码]
     */
    protected function make_str($chars = '', $length = 18)
    {
        static $code;
        $last = '';
        do {
            $last = $code;
            $code = '';
            for ($i = 0; $i < $length; ++$i) {
                $code .= $chars[mt_rand(0, strlen($chars) - 1)];
            }
        } while (substr($code, 0, 1) === '0');

        return $code;
    }

    /**
     *  AES 加密.
     */
    public function hxfy_encrypt($plaintext, $key, $iv)
    {
        $plaintext = trim($plaintext);
        if ($plaintext == '') {
            return '';
        }

        $encrypted = openssl_encrypt($plaintext, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);

        return strtoupper(bin2hex($encrypted));
    }

    /**
     *  AES 解密.
     */
    public function hxfy_decrypt($encrypted, $key, $iv)
    {
        if ($encrypted == '') {
            return '';
        }

        $ciphertext_dec = @hex2bin($encrypted);

        $decrypted = openssl_decrypt($ciphertext_dec, 'AES-128-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);

        return special_filter($decrypted);
        //return trim($decrypted);
    }

    /** 
     * @Author: liuyunliang 
     * @Date: 2019-05-27 21:01:30 
     * @Desc: 七牛云图片上传
     * @update:    
     */    
    public function qi_niu($file)
    {
        $path = $file->getRealPath();
        $ext = pathinfo($file->getInfo('name'), PATHINFO_EXTENSION);
        $key = 'huaxia/' .date('Ymd') . '/' . str_replace('.', '0', microtime(1)) . '.' . $ext;
        $ym = config('Qiniu_token.ym');
        include_once '../extend/Qiniu/autoload.php';
        $accessKey = config('Qiniu_token.accessKey');
        $secretKey = config('Qiniu_token.secretKey');
        $auth = new Auth($accessKey, $secretKey);
        $bucket = config('Qiniu_token.bucket');
        $token = $auth->uploadToken($bucket);
        $upload = new UploadManager();
        list($ret, $err) = $upload->putFile($token, $key, $path);
        $image = $ym.'/'.$ret['key'];
        return $image;
    }


    /*
     * 上传文件
     * @param $file 文件流
     * @param $upload_path 保存路径
     */
    public function upload_file($file, $upload_path = '')
    {
        if (empty($upload_path)) {
            $upload_path = ROOT_PATH . 'public' . DS . 'static' . DS . 'uploads' . DS;
        }

        $info = $file->rule('uniqid')->move($upload_path);
        if ($info) {
            return array(
                'code' => '0',
                'save_name' => $info->getSaveName(),
            );
        } else {
            return array(
                'code' => '1',
                'error' => $file->getError(),
            );
        }
    }

    /**
     * 敏感词检查
     * @author JiaoYuXin
     */
    protected function mgcCheck($world)
    {
        $example = new SensitiveWordTree();

        $path = APP_PATH.'../public/resource/mgcdata/limit_words.txt';
        if( !is_file($path) ){
            return [];
        }

        // 敏感词
        $ci = file_get_contents($path);
        if(empty($ci)){
            return [];
        }

        $sensitiveWordList = explode("\n",$ci);
        if(empty($sensitiveWordList)){
            return [];
        }

        foreach ($sensitiveWordList as $eachWord) {
            $example->addWordToTree($eachWord);
        }
        $exampleStr = $world.' ';

        $result = $example->search($exampleStr);

        return $result;
    }
    // -----------------------------------------------------------------------------------------------------------------
}
