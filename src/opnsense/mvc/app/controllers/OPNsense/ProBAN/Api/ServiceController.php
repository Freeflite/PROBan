<?php

namespace OPNsense\ProBAN\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Service control for the ProBAN engine (start/stop/restart/status) plus the
 * standard reconfigure that regenerates config.json + rc.conf.d from the model.
 * reconfigure also reloads the firewall so the block/rdr rules track the settings.
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\ProBAN\General';
    protected static $internalServiceTemplate = 'OPNsense/ProBAN';
    protected static $internalServiceName = 'proban';

    protected function ServiceEnabled()
    {
        return (string)$this->getModel()->enabled === '1';
    }

    public function reconfigureAction()
    {
        $result = parent::reconfigureAction();
        if (isset($result['status']) && $result['status'] === 'ok') {
            // pick up block/rdr rule changes from proban_firewall()
            (new Backend())->configdRun('filter reload');
        }
        return $result;
    }
}
