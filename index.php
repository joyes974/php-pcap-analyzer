<?php
//  PHP PCAP Analyzer
//	Copyright (c) 2011, Todd Tanner
//	All rights reserved.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	    * Redistributions of source code must retain the above copyright
//	      notice, this list of conditions and the following disclaimer.
//	    * Redistributions in binary form must reproduce the above copyright
//	      notice, this list of conditions and the following disclaimer in the
//	      documentation and/or other materials provided with the distribution.
//	    * Neither the name of the <organization> nor the
//	      names of its contributors may be used to endorse or promote products
//	      derived from this software without specific prior written permission.
//
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set_time_limit(0);
session_start();
# PCAP log file interpreter
# references
# LibpcapFileFormat - http://wiki.wireshark.org/Development/LibpcapFileFormat#Libraries
# ipv4 packet - http://www.networkur.com/ipv4-packet-format/
# TCP Protocol - http://en.wikipedia.org/wiki/Transmission_Control_Protocol

####################  Class Objects  ####################
// pcap file header - 24 bytes
class pcap_hdr_s {
	public $magic_number; 	// either d4c3b2a1 or a1b2c3d4 (on disk d4c3b2a1)
	public $version_major;
	public $version_minor;
	public $thiszone;
	public $sigfigs;
	public $snaplen;
	public $network;
	public $records;
	public $size = 0;
}
// pcap record header - 16 bytes
class pcap_record {
	public $index;
	// actual headr data is only the 4 below variables
	public $ts_sec;
	public $ts_usec;
	public $incl_len;
	public $orig_len;
	// the variables below are holders for other headers and the packet data itself
	public $eth; 	// ethernet header
	public $ip;		// ip header
	public $tcp;	// tcp header and data
}
// ethernet packet header - 14 bytes
class ethernet_header {
	public $dest_mac; 	// 48 bit mac address
	public $src_mac;	// 48 bit mac address
	public $type;	// 16 bit ethernet type - IP, ARP, RARP, etc
}
// ipv4 packet - 24 bytes (min)
class ipv4_packet {
	public $ver;		// 4 bits
	public $hdr_len;	// 4 bits
	public $tos;		// 8 bits
	public $total_len;	// 16 bits
	public $ident;		// 16 bits
	public $flags;		// 4 bits
	public $frag_off;	// 12 bits
	public $ttl;		// 8 bits
	public $proto;		// 8 bits
	public $checksum;	// 16 bits
	public $checksum_calc;
	public $src;		// 32 bits
	public $dest;		// 32 bits
	public $src_ip;		// 32 bits
	public $dest_ip;		// 32 bits
	public $options;
}
// tcp header - 20 bytes (min)
class tcp_header {
	// for pseudo header
	public $src;	// 32 bits
	public $dest;	// 32 bits
	//
	public $src_port;
	public $dest_port;
	public $seq;
	public $ack;
	public $data_offset;

	// Flags
	public $flags;	//holds flag decimal value
	// acutal bit flags
	public $fcwr;
	public $fece;
	public $furg;
	public $fack;
	public $fpsh;
	public $frst;
	public $fsyn;
	public $ffin;
	//
	public $window;
	public $checksum;
	public $checksum_calc;
	public $urg;
	public $options;
	public $data = '';
}
// a simple file system object
class fs_file {
	var $name; 	// Ex. apple.txt, folder_name
	var $isDir;
	var $isFile;
	var $size;	// Ex. 0, 2354623
	var $ext;	// Ex. jpg, txt, css, php
	var $type; // Registered file type for this file's extension (Ex. jpg, jpeg, txt, html)
	var $modified;
	var $path = '';
	var $realPath;
	var $basePath;
    var $displayPath; 	// the path as shown in an address bar (no password)
    var $fullPath;		// full path with username, password, port, etc included
	var $isReadable;
	var $isWritable;
	var $isExecutable;
}
####################  Functions  ####################
function valid_pcap($fname){
	if (!file_exists ($fname)){
		return false;
	}
	if (filesize($fname) < 31) {
		return null;
	}
	$b = file_get_contents($fname, NULL, NULL, 0, 4);
	$lng = byte_array_to_long($b,0);
	$lng = byte_array_to_long($b,0);
	if (dechex($lng) == 'a1b2c3d4') {
		return true;
	} else {
		return false;
	}
}
function index_pcap($fname){
	$offset = 24;
	$len_off = 8;
	$ri = array();
	if (valid_pcap($fname)) {
		$fs = filesize($fname);
		$ri[] = $offset; // record position array
		while ($fs > $offset + 4){
			$b = file_get_contents($fname, NULL, NULL, $offset + $len_off, 4);
			$offset += byte_array_to_long($b) + 16;
			if ($fs > $offset){
				$ri[] = $offset;
			}
		}
	}
	return $ri;
}
function parse_pcap($fname,$start_rec=0,$max){
	$hdr = null;
	if (valid_pcap($fname)) {
		$cnt = 0;
		$hdr = new pcap_hdr_s();
		$hdr->records = array();
		$hdr->size = filesize($fname);
		$b = file_get_contents($fname, NULL, NULL, 0, 24);
		$lng = byte_array_to_long($b,0);
		$hdr->magic_number = $lng;
		$hdr->version_major = byte_array_to_int($b,4);
		$hdr->version_minor = byte_array_to_int($b,6);
		$hdr->thiszone = byte_array_to_long($b,8);
		$hdr->sigfigs = byte_array_to_long($b,12);
		$hdr->snaplen = byte_array_to_long($b,16);
		$hdr->network = byte_array_to_long($b,20);
		$offset = 24;
		if ($hdr->network == 1) {
			// link type was expected. continue
			while ($offset + 54 < $hdr->size) {
				$off = $offset;
				$cnt++;
				$pr = new pcap_record();
				$b = file_get_contents($fname, NULL, NULL, $offset, 16);
				$pr->ts_sec = byte_array_to_long($b,0);
				$pr->ts_usec = byte_array_to_long($b,4);
				$pr->incl_len = byte_array_to_long($b,8);
				$pr->orig_len = byte_array_to_long($b,12);
				$off += 16;
				if ($start_rec < $cnt) {
					if ($pr->incl_len < 0 || $pr->orig_len < 0) {
						echo "Error parsing";
						break;
					} else {
						// ethernet header
						$pr->eth = parse_ethernet_header($fname,$off);
						$off += 14; // add size of ethernet packet header
						// ip header
						$pr->ip = parse_ip($fname,$off);
						$off += $pr->ip->hdr_len * 4; // add size of ip packet header
						if ($pr->ip->proto == 6){
							// tcp
							$pr->tcp = parse_tcp($fname,$off,$pr->ip->src,$pr->ip->dest,$pr->incl_len - (14 + ($pr->ip->hdr_len * 4)));
							$off += $pr->tcp->data_offset * 4; // add size of tcp packet header
							// data
							$dend = $pr->incl_len - (14 + ($pr->ip->hdr_len * 4) + ($pr->tcp->data_offset * 4));
							$pr->tcp->data = file_get_contents($fname, NULL, NULL, $off, $dend);
						} elseif ($pr->ip->proto == 17){
							// udp
						} elseif ($pr->ip->proto == 1){
							// icmp
						}
					}
					$pr->index = $cnt;
					$hdr->records[] = $pr;
					if (count($hdr->records) == $max){
						break;
					}
				}
				$offset += $pr->incl_len + 16;
			}
		} else {
			echo 'Unknown network link type';
		}
	} else {
		echo "Invalid pcap file";
	}
	return $hdr;
}
function get_now(){
	return date("Y-m-d H:i:s",time());
}
function been_parsed($fname){
	$path_parts = pathinfo($fname);
	$dir = preg_replace('#.pcap$#i','',$path_parts['basename']);
	$ret = false;
	$fs = filesize($fname);
	if (is_dir('./'.$dir) && file_exists($dir . '/' . $fs . ".htm")){
		$ret = true;
	}
	return $ret;
}
function clean_dir($dir){
	$dir = rtrim(realpath($dir),'/') . '/';
	$tmp = browse($dir);
//	foreach ($tmp as $f){
//		unlink($dir . $f->name);
//	}
//	$tmp = browse($dir,'.seq');
//	foreach ($tmp as $f){
//		unlink($dir . $f->name);
//	}
//	$tmp = browse($dir,'.raw');
	foreach ($tmp as $f){
		if ($f->isFile){
			unlink($dir . $f->name);
		}
	}
}
function dump_pcap($fname,$force=false){
	$hdr = null;
	$path_parts = pathinfo($fname);
	$dir = preg_replace('#.pcap$#i','',$path_parts['basename']);
	if (!is_dir('./'.$dir)){
		mkdir('./'.$dir);
	}
	$ret = '';
	$fs = filesize($fname);
	if (file_exists($dir . '/' . $fs . ".htm") && !$force){
		$ret = "Previously parsed<br/>" . file_get_contents($dir . '/' . $fs . ".htm");
		return $ret;
	}
	clean_dir($dir);
	$ret = $fname . "<br/>" . get_now() . "<br/><br/>";
	if (valid_pcap($fname)) {
		$cnt = 0;
		$hdr = new pcap_hdr_s();
		$hdr->records = array();
		$hdr->size = $fs;
		$b = file_get_contents($fname, NULL, NULL, 0, 24);
		$lng = byte_array_to_long($b,0);
		$hdr->magic_number = $lng;
		$hdr->version_major = byte_array_to_int($b,4);
		$hdr->version_minor = byte_array_to_int($b,6);
		$hdr->thiszone = byte_array_to_long($b,8);
		$hdr->sigfigs = byte_array_to_long($b,12);
		$hdr->snaplen = byte_array_to_long($b,16);
		$hdr->network = byte_array_to_long($b,20);
		$offset = 24;
		if ($hdr->network == 1) {
			// link type was expected. continue
			while ($offset + 54 < $hdr->size) {
				$off = $offset;
				$cnt++;
				$pr = new pcap_record();
				$b = file_get_contents($fname, NULL, NULL, $offset, 16);
				$pr->ts_sec = byte_array_to_long($b,0);
				$pr->ts_usec = byte_array_to_long($b,4);
				$pr->incl_len = byte_array_to_long($b,8);
				$pr->orig_len = byte_array_to_long($b,12);
				$off += 16;
				if ($pr->incl_len < 0 || $pr->orig_len < 0) {
					$ret .= "Error parsing";
					break;
				} else {
					// ethernet header
					$pr->eth = parse_ethernet_header($fname,$off);
					$off += 14; // add size of ethernet packet header
					// ip header
					$pr->ip = parse_ip($fname,$off);
					$off += $pr->ip->hdr_len * 4; // add size of ip packet header
					if ($pr->ip->proto == 6){
						// tcp
						$pr->tcp = parse_tcp($fname,$off,$pr->ip->src,$pr->ip->dest,$pr->incl_len - (14 + ($pr->ip->hdr_len * 4)));
						$off += $pr->tcp->data_offset * 4; // add size of tcp packet header
						// data
						$dend = $pr->incl_len - (14 + ($pr->ip->hdr_len * 4) + ($pr->tcp->data_offset * 4));
						if ($dend > 0){
							$pr->tcp->data = file_get_contents($fname, NULL, NULL, $off, $dend);
							if ($pr->tcp->data != "\x00\x00\x00\x00\x00\x00"){
								$fn = $pr->ip->src_ip . "-" . $pr->tcp->src_port;
								$fn .= "--" . $pr->ip->dest_ip . "-" . $pr->tcp->dest_port;
								$fn .= "--" . $pr->tcp->ack;
								$seq = 0;
								if (file_exists($dir . '/' . $fn . ".seq")){
									$seq = file_get_contents($dir . '/' . $fn . ".seq");
								}
								//$se = chr(($pr->tcp->seq >> 24) & 0xff) . chr(($pr->tcp->seq >> 16) & 0xff) . chr(($pr->tcp->seq >> 8) & 0xff) . chr($pr->tcp->seq & 0xff);
								if ($pr->tcp->seq > $seq){
									// is packet unique?
									file_put_contents($dir . '/' . $fn . ".seq",$pr->tcp->seq);
									file_put_contents($dir . '/' . $fn . ".raw",$pr->tcp->data,FILE_APPEND);
								}
							}
						}
					} elseif ($pr->ip->proto == 17){
						// udp
					} elseif ($pr->ip->proto == 1){
						// icmp
					}
				}
				$pr->index = $cnt;
				$offset += $pr->incl_len + 16;
			}
		} else {
			$ret .= "Unknown network link type<br/>";
		}
	} else {
		$ret .= "Invalid pcap file<br/>";
	}
	$ret .= parse_streams($fname);
	file_put_contents($dir . '/' . $fs . ".htm",$ret);
	return $ret;
}
function parse_streams($fname,$force=false){
	$path_parts = pathinfo($fname);
	$dir = preg_replace('#.pcap$#i','',$path_parts['basename']);
	$tmp = browse($dir,'.raw');
	$cnt = 0;
	$ret = '';
	foreach ($tmp as $f){
		$processed = false;
		$tmp = preg_replace('#---?[0-9]*\.raw#','',$f->name);
		$tmp = preg_replace('#--#',' > ',$tmp);
		$tmp = preg_replace('#-#',':',$tmp);
		$ret .= $tmp . "<br/>";
		$b = file_get_contents($dir . '/' . $f->name);
		if (strpos($b,'HTTP') === 0){
			// HTTP server response
			$ret .= '<span style="color:blue;">';
			$processed = true;
			$ret .= "HTTP Response<br/>";
			// HTTP reply
			if (strpos($b,"\r\n\r\n")){
				$hdr = substr($b,0,strpos($b,"\r\n\r\n"));
				$b = substr($b,strpos($b,"\r\n\r\n") + 4);
				$ct = '';
				if (preg_match('#content-type: (.*)#i',$hdr,$m)){
					$ret .= "Content-type: " . $m[1] . "<br/>";
					$ct = $m[1];
				}
				if (preg_match('#content-encoding: (.*)#i',$hdr,$m)){
					$ret .= "Content-encoding: " . $m[1] . "<br/>";
					$ce = $m[1];
					if (preg_match('/gzip/i',$ce)){
						$b = gzip_decode($b);
					}
				}
				// parse data
				if ($b != ''){
					if (preg_match('/jpeg/i',$ct)){
						$new = preg_replace('#.raw$#i','.jpg',$f->name);
						file_put_contents($dir . '/' . $new,$b);
						$src = preg_replace('#.pcap$#i','',$fname) . '/';
						$ret .= '<img src="' . $dir . '/' . $new . '"/><br/>';
					} elseif (preg_match('/gif/i',$ct)){
						$new = preg_replace('#.raw$#i','.gif',$f->name);
						file_put_contents($dir . '/' . $new,$b);
						$src = preg_replace('#.pcap$#i','',$fname) . '/';
						$ret .= '<img src="' . $dir . '/' . $new . '"/><br/>';
					} elseif (preg_match('/text/i',$ct)){
						$ret .= "<pre><code>";
						$txt = preg_replace('#</?[a-z].*?/?>#i','',$b);
						$txt = preg_replace('/\r\n/','<br/>',$txt);
						$txt = preg_replace('/\n/','<br/>',$txt);
						$ret .= $txt;
						$ret .= "</code></pre>";
					} else {
						$ret .= "No filetype match found<br/>";
					}
				}
			} else {
				$ret .= "empty HTTP reply<br/>";
			}
			$ret .= "</span>";
		} elseif (preg_match('/^(GET|POST) ([^ ]*) HTTP.*?\r\n((?:.+?\r\n)*)(?:\r\n(.*))?/msi',$b,$m)){
			// HTTP POST or GET request
			$processed = true;
			$req_type = $m[1];
			$page = $m[2];
			$hdr = $m[3];
			$dat = urldecode($m[4]);
			if (strtoupper($req_type) == 'POST'){
				$ret .= '<span style="color:red;">';
			} else {
				$ret .= '<span style="color:green;">';
			}
			if (preg_match('#host: (.*)\r\n#i',$hdr,$m)){
				$ret .= $req_type . ' <a href="http://'.$m[1].'">' . $m[1] .'</a><a href="http://'.$m[1].$page.'">' . $page . "</a><br/>";
			}
			if (preg_match('#user-agent: (.*)\r\n#i',$hdr,$m)){
				$ret .= "User-agent: " . $m[1] . "<br/>";
			}
			if (preg_match('#referer: (.*)\r\n#i',$hdr,$m)){
				$ret .= 'Referer: <a href="'.$m[1].'">' . preg_replace('#^http://#i','',$m[1]) .'</a><br/>';
			}
			if (strtoupper($req_type) == 'POST'){
				$dat = trim($dat);
				if ($dat != ''){
					$dat = preg_replace('#&#',"\n",$dat);
					$dat = preg_replace('#<#','&lt;',$dat);
					$dat = preg_replace('#>#','&gt;',$dat);
					$ret .= "<pre><code>";
					$ret .= $dat;
					$ret .= "</code></pre>";
				}
			}
			$ret .= "</span>";
		} else {
			$ret .= "No protocol match found for ".conv_bytes(strlen($b))."<br/>";
		}
		$ret .= "<br/>";
		if ($processed){
			$cnt++;
			unlink($dir . '/' . $f->name);
			unlink(preg_replace('#.raw$#i','.seq',$dir . '/' . $f->name));
		}
	}
	return $ret;
}
function gzip_decode($res){
	$res = '...';
	return $res;

}
function parse_tcp($fname,$offset,$src,$dest,$size){
	$eh = null;
	if ($offset > 0) {
		$eh = new tcp_header();
		$b = file_get_contents($fname, NULL, NULL, $offset, 20);
		$eh->src_port = byte_array_to_int($b,0,1);
		$eh->dest_port = byte_array_to_int($b,2,1);
		$eh->seq = byte_array_to_long($b,4,1);
		$eh->ack = byte_array_to_long($b,8,1);
		$eh->data_offset = byte_array_to_nib($b,12,1);
		// flags
		$eh->flags = ord($b[13]);	// flags byte
		$eh->fcwr = get_bit($eh->flags,7);
		$eh->fece = get_bit($eh->flags,6);
		$eh->furg = get_bit($eh->flags,5);
		$eh->fack = get_bit($eh->flags,4);
		$eh->fpsh = get_bit($eh->flags,3);
		$eh->frst = get_bit($eh->flags,2);
		$eh->fsyn = get_bit($eh->flags,1);
		$eh->ffin = get_bit($eh->flags,0);
		//
		$eh->window = byte_array_to_int($b,14,1);
		$eh->checksum = byte_array_to_int($b,16,1);
		$eh->urg = byte_array_to_int($b,18,1);
		if ($eh->data_offset > 5) {
			$eh->options = file_get_contents($fname, NULL, NULL, $offset + 20, ($eh->data_offset * 4) - 20);
		}
		// checksum
		$si[0] = chr($size & 0xff);
		$si[1] = chr(($size >> 8) & 0xff);
		$b = $src . $dest;
		$b .= chr(0); 	// reserved
		$b .= chr(6);	// protocol (tcp = 6)
		$b .= $si[1] . $si[0];	// tcp len
		$ba = file_get_contents($fname, NULL, NULL, $offset, $size);
		$ba[16] = chr(0);
		$ba[17] = chr(0);
		$b .= $ba;
		$eh->checksum_calc = calc_checksum($b,true);
	}
	return $eh;
}
function parse_ethernet_header($fname,$offset){
	$eh = null;
	if ($offset > 0) {
		$eh = new ethernet_header();
		$b = file_get_contents($fname, NULL, NULL, $offset, 14);
		$eh->dest_mac = str2hex($b,0,6);
		$eh->src_mac = str2hex($b,6,6);
		$eh->type = byte_array_to_int($b,12);
	}
	return $eh;
}
function str2hex($string,$offset=0,$len=0,$delim=':'){
    $hex='';
    if ($len == 0) {
    	$len = strlen($string);
    }
    for ($i=0; $i < $len; $i++){
    	if ($hex != '') {
    		$hex .= $delim;
    	}
    	$tmp = strtoupper(dechex(ord($string[$i + $offset])));
    	if (strlen($tmp) == 1){
    		$tmp = '0' . $tmp;
    	}
        $hex .= $tmp;
    }
    return $hex;
}
function parse_ip($fname,$offset){
	$p = null;
	if ($offset > 0) {
		$p = new ipv4_packet();
		$b = file_get_contents($fname, NULL, NULL, $offset, 20);
		$p->ver = byte_array_to_nib($b,0,1);		// 4 bits 54 136
		if ($p->ver == 4) {
			// ipv4
			$p->hdr_len = byte_array_to_nib($b,0,0);	// 4 bits 54
			$p->tos = ord($b[1]);						// 8 bits 55
			$p->total_len = byte_array_to_int($b,2);	// 16 bits 56
			$p->ident = byte_array_to_int($b,4);		// 16 bits 58
			$p->flags = byte_array_to_nib($b,6,1);		// 4 bits 60
			$p->frag_off = (byte_array_to_nib($b,6,0) << 8)+ ord($b[7]);					// 12 bits 60
			$p->ttl = ord($b[8]);						// 8 bits 62
			$p->proto = ord($b[9]);						// 8 bits 63
			$p->checksum = byte_array_to_int($b,10);	// 16 bits 64
			$p->src_ip = long2ip(byte_array_to_long($b,12,1));		// 32 bits pos 66 148
			$p->dest_ip = long2ip(byte_array_to_long($b,16,1));		// 32 bits pos 70

			$p->src = substr($b,12,4);		// 32 bits pos 66 148
			$p->dest = substr($b,16,4);		// 32 bits pos 70

			if ($p->hdr_len > 5) {
				$p->options = file_get_contents($fname, NULL, NULL, $offset + 20, ($p->hdr_len * 4) - 20);
			}
			// do checksum on data
			// create psuedo header for checksum
			// The pseudo header contains the Source Address, the Destination Address,
			// the Protocol, and TCP length
			$b = file_get_contents($fname, NULL, NULL, $offset, $p->hdr_len * 4);
			$b[10] = "\x00";
			$b[11] = "\x00";
			$p->checksum_calc = calc_checksum($b);
		} else {
			// ipv6
		}
	}
	return $p;
}
function rel_path($spath){
	$docroot = $_SERVER['DOCUMENT_ROOT'];
	$docroot = rtrim($$docroot,'/');
	if (stripos($spath,$docroot) === 0) {
		return substr($spath,strlen($docroot));
	}
}
function parse_unsigned_int($string) {
	$x = (float)$string;
	if ($x > (float)2147483647)
		$x -= (float)"4294967296";
	return (int)$x;
}
function byte_array_to_long($b,$start_index = 0,$bend_force = -1){
	global $bend;
	if ($bend_force == -1){
		$bend_force = $bend;
	}
	if ($bend_force){
		$lng = (ord($b[$start_index]) << 24) + (ord($b[$start_index+1]) << 16) + (ord($b[$start_index+2]) << 8) + (ord($b[$start_index+3]));
	} else {
		$lng = ord($b[$start_index]) + (ord($b[$start_index+1]) << 8) + (ord($b[$start_index+2]) << 16) + (ord($b[$start_index+3]) << 24);
	}
	return $lng;
}
function byte_array_to_int($b,$start_index = 0,$bend_force = -1){
	global $bend;
	if ($bend_force == -1){
		$bend_force = $bend;
	}
	if ($bend_force){
		$lng = (ord($b[$start_index]) << 8) + ord($b[$start_index+1]);
	} else {
		$lng = ord($b[$start_index]) + (ord($b[$start_index+1]) << 8);
	}
	return $lng;
}
function get_bit($b,$bit=1){
	$lng = $b & (1 << $bit);
	$lng = $lng >> $bit;
	return $lng;
}
function byte_array_to_nib($b,$start_index = 0,$high_nib=true){
	if ($high_nib) {
		$lng = ord($b[$start_index]) >> 4;
	} else {
		$lng = ord($b[$start_index]) & 15;
	}
	return $lng;
}
function conv_bytes($bytecnt) {
    $t = $bytecnt;
    if (number_format($t / 1024, 2) >= 1) {
	$t = $t / 1024;
	if (number_format($t / 1024, 2) >= 1) {
	    $t = $t / 1024;
	    if (number_format($t / 1024, 2) >= 1) {
		$t = $t / 1024;
		$ret = number_format($t, 2) . ' GB';
	    } else {
		$ret = number_format($t, 2) . ' MB';
	    }
	} else {
	    $ret = number_format($t, 2) . ' KB';
	}
    } else {
	$ret = $bytecnt . ' bytes';
    }
    return $ret;
}
function browse($newpath,$filter='') {
    $mpath = $newpath;
	$info = new SplFileInfo($newpath);
	if (!$info->isDir()) {
		return false;
	}
	$newpath = $info->getRealPath();
	//$this->path = $mpath;
	//$this->real_path = $newpath;
	// permissions check here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	$iterator = new DirectoryIterator($newpath);
	//$iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::SELF_FIRST);
	// could use CHILD_FIRST if you so wish
	$size = 0;
	$res = array();
	foreach ($iterator as $file) {
		if ($file->getBasename() != '.' && $file->getBasename() != '..') {
			$f = new fs_file();
			$f->name = $file->getBasename();
			$f->path = $file->getPath();
			$f->realPath = $file->getRealPath();
			$f->isFile = $file->isFile();
			$f->isDir = !$f->isFile;
			$f->size = $file->getSize();
			$f->modified = $file->getMTime();
			$f->isReadable = $file->isReadable();
			$f->isWritable = $file->isWritable();
			$f->isExecutable = $file->isExecutable();
			if ($filter == '' || strpos($f->name,$filter)){
				$res[] = $f;
			}
		} else {
			$stop = '';
		}
	}
	return $res;
}
function calc_checksum($b,$bigendian=false){
	if (strlen($b)%2)
		$b .= "\x00";
    $sum = 0;
	for ($i=0;$i<strlen($b);$i=$i+2){
		if ($bigendian) {
			$sum += byte_array_to_int($b,$i,1);
		} else {
			$sum += byte_array_to_int($b,$i);
		}
	}
   while ($sum >> 16)
       $sum = ($sum >> 16) + ($sum & 0xffff);

   $sum = ~$sum;
   $sum = $sum & 0xffff;
   return $sum;
}
function list_pcap_files($dir){
	$ret = '';
	$dir = rtrim(realpath($dir),'/') . '/';
	$ret .= "PCAPs found - " . $dir . "<br/>\n";
	$tmp = browse($dir,'.pcap');
	$ret .= '<a href="index.php">Browse</a><br/>';
	foreach ($tmp as $f){
		$ret .= '<a href="index.php?file='.$f->name.'">'.$f->name.'</a> - ' . conv_bytes($f->size);
		if (been_parsed($dir . $f->name)){
			$ret .= ' (Done/<a href="index.php?file='.$f->name.'&force=1">Refresh</a>)';
		}
		$ret .= "<br/>";
	}
	$ret .= "<br/>";
	return $ret;
}
####################  Main  ####################
$pcapdir = 'test_data';
// Set $pcapdir to the folder where you keep your .pcap files
// only .pcap files will be listed
$pcapdir = rtrim(realpath($pcapdir),'/') . '/';
$bend = false;
$fname = '';
$ret = '';
if (isset($_GET['file']) && $_GET['file'] != ''){
	if (!preg_match('#\/#',$_GET['file'])){
		//if (!preg_match('#*#',$_GET['file']) && !preg_match('#\\#',$_GET['file'])){
			$fname = $pcapdir . $_GET['file'];
		//}
	}
}
if (isset($_GET['force']) && $_GET['force'] == 1){
	$force = true;
} else {
	$force = false;
}
if ($fname != ''){
	$ret = dump_pcap($fname,$force);
}
?>
<html><head><title>PCAP Analyzer<?php if ($fname != ''){ echo " - $fname";}?></title></head>
<body>
<div style="width:100%">
<?php
echo list_pcap_files($pcapdir);
echo $ret;
?>
</div>
</body>
</html>
