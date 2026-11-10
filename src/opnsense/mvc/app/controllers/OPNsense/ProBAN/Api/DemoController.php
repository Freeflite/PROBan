<?php

namespace OPNsense\ProBAN\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\ProBAN\General;
use OPNsense\Core\Backend;

/**
 * ProBAN demo-mode API.
 *
 * Populates / clears SYNTHETIC offenders so the dashboard can be evaluated with
 * a realistic data set. This is a loaded capability to expose in a security
 * plugin, so it is gated:
 *
 *   - Seeding requires the demo_mode setting to be enabled (enforced here, not
 *     just hidden in the UI), so a crafted request on a box with demo mode off
 *     does nothing.
 *   - Every synthetic row is confined to the non-routable RFC 2544 block
 *     (198.18.0.0/15) by demo_seed.py; it can never reach a real host.
 *   - Purge is always allowed (even with demo mode off) so synthetic data can
 *     always be cleaned up.
 *
 * After each change a one-shot `proban run` syncs the pf tables so the block
 * table and the dashboard reflect the new state promptly.
 */
class DemoController extends ApiControllerBase
{
    private function demoEnabled()
    {
        $mdl = new General();
        return ((string)$mdl->demo_mode === "1");
    }

    private function decode($raw)
    {
        $res = json_decode(trim((string)$raw), true);
        return is_array($res) ? $res : null;
    }

    public function seedAction()
    {
        if (!$this->request->isPost()) {
            return ["status" => "error", "msg" => "POST required"];
        }
        if (!$this->demoEnabled()) {
            return ["status" => "error", "msg" => "demo mode is disabled"];
        }
        $count = (int)$this->request->getPost("count", "int", 5000);
        $count = max(1, min($count, 50000));

        $backend = new Backend();
        $res = $this->decode($backend->configdpRun("proban demoseed", [(string)$count]));
        if ($res === null) {
            return ["status" => "error", "msg" => "seed failed"];
        }
        // Push the freshly-seeded blocks into pf (no-op in dry-run) so the
        // block table and stats catch up without waiting for the next cycle.
        $backend->configdRun("proban run");

        $res["status"] = "ok";
        return $res;
    }

    public function purgeAction()
    {
        if (!$this->request->isPost()) {
            return ["status" => "error", "msg" => "POST required"];
        }
        $backend = new Backend();
        $res = $this->decode($backend->configdRun("proban demopurge"));
        if ($res === null) {
            return ["status" => "error", "msg" => "purge failed"];
        }
        $backend->configdRun("proban run");

        $res["status"] = "ok";
        return $res;
    }
}
