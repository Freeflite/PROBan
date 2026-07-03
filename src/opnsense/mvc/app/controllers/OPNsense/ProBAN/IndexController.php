<?php
namespace OPNsense\ProBAN;
class IndexController extends \OPNsense\Base\ControllerBase
{
    public function indexAction()
    {
        $this->view->title = "Progressive Ban (ProBAN)";
        $this->view->pick('OPNsense/ProBAN/index');
    }
}
