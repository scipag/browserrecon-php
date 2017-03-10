<?php

/*
+--------------------------------------------------------------------+
|	browserrecon 1.4-php
|
|	(c) 2008 by Marc Ruef
|	marc.ruef@computec.ch
|	http://www.computec.ch/projekte/browserrecon/
|
|	Released under the terms and conditions of the
|	GNU General Public License 3.0 (http://gnu.org).
|
|	Installation:
|	Extract the archive in a folder accessible by your
|	web browser. Include the browserrecon script with
|	the following function call:
|		include('browserrecon/inc_browserrecon.php');
|
|	Use:
|	Use the function browserrecon() to do a web browser
|	fingerprinting with the included utility. The first
|	argument of the function call is the raw http headers
|	sent by the client. You might use the following
|	call to do a live fingerprinting of visiting users:
|		echo browserrecon(getfullheaders());
|
|	It is also possible to get the data from another
|	source. For example a local file named header.txt:
|		echo browserrecon(file_get_contents('header.txt')));
|
|	Or the data sent via a http post form:
|		echo browserrecon($_POST['header']);
|
|	Reporting:
|	You are able to change the behavior of the reports
|	sent back by browserrecon(). As second argument you
|	might use the following parameters:
|		- simple: Identified implementation only
|		- besthitdetail: Additional hit detail
|		- list: Unordered list of all matches
|		- besthitlist: Top ten list of the best matches
|
+--------------------------------------------------------------------+
*/

// Main Function
function browserrecon($rawheader, $mode='besthit', $database=''){
	return announcefingerprintmatches(generatematchstatistics(identifyglobalfingerprint($database, $rawheader)), $mode, counthitpossibilities($rawheader));
}

// Header Extraction
function getfullheaders(){
	$headers = getallheaders();
	
	foreach($headers as $header => $value){
		$full_header.= $header.': '.$value."\n";
	}

	return $full_header;
}

function getheadervalue($rawheader, $headername){
	$headers = explode("\n", $rawheader, 64);
	$headernamesmall = strtolower($headername);

	foreach($headers as $header){
		$header_data = explode(':', $header, 2);
		if(strtolower($header_data['0']) == $headernamesmall){
			return trim($header_data['1']);
		}
	}
}

function getheaderorder($rawheader){
	$headers = explode("\n", $rawheader, 64);
	$headers_count = count($headers);

	for($i=0; $i<$headers_count; ++$i){
		$header_data = explode(':', $headers[$i], 2);

		if(strlen($header_data['0']) > 2){
			$header_order.= trim($header_data['0']);

			if(strlen($headers[$i+1]) > 0){
				$header_order.= ', ';
			}
		}
	}

	return $header_order;
}

function counthitpossibilities($rawheader){
	(getheadervalue($rawheader, 'User-Agent') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Accept') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Accept-Language') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Accept-Encoding') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Accept-Charset') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Keep-Alive') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Connection') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'Cache-Control') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'UA-Pixels') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'UA-Color') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'UA-OS') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'UA-CPU') != '' ? ++$count : '');
	(getheadervalue($rawheader, 'TE') != '' ? ++$count : '');
	(getheaderorder($rawheader) != '' ? ++$count : '');

	return $count;
}

// Database Search
function identifyglobalfingerprint($database, $rawheader){
	$matchlist = findmatchindatabase($database.'user-agent.fdb', getheadervalue($rawheader, 'User-Agent'));
	$matchlist.= findmatchindatabase($database.'accept.fdb', getheadervalue($rawheader, 'Accept'));
	$matchlist.= findmatchindatabase($database.'accept-language.fdb', getheadervalue($rawheader, 'Accept-Language'));
	$matchlist.= findmatchindatabase($database.'accept-encoding.fdb', getheadervalue($rawheader, 'Accept-Encoding'));
	$matchlist.= findmatchindatabase($database.'accept-charset.fdb', getheadervalue($rawheader, 'Accept-Charset'));
	$matchlist.= findmatchindatabase($database.'keep-alive.fdb', getheadervalue($rawheader, 'Keep-Alive'));
	$matchlist.= findmatchindatabase($database.'connection.fdb', getheadervalue($rawheader, 'Connection'));
	$matchlist.= findmatchindatabase($database.'cache-control.fdb', getheadervalue($rawheader, 'Cache-Control'));
	$matchlist.= findmatchindatabase($database.'ua-pixels.fdb', getheadervalue($rawheader, 'UA-Pixels'));
	$matchlist.= findmatchindatabase($database.'ua-color.fdb', getheadervalue($rawheader, 'UA-Color'));
	$matchlist.= findmatchindatabase($database.'ua-os.fdb', getheadervalue($rawheader, 'UA-OS'));
	$matchlist.= findmatchindatabase($database.'ua-cpu.fdb', getheadervalue($rawheader, 'UA-CPU'));
	$matchlist.= findmatchindatabase($database.'te.fdb', getheadervalue($rawheader, 'TE'));
	$matchlist.= findmatchindatabase($database.'header-order.fdb', getheaderorder($rawheader));

	return $matchlist;
}

function addtodatabase($databasefile, $implementation, $value){
	if(strlen($implementation) && strlen($value)){
		if(!isindatabase($databasefile, $implementation, $value)){
			if(is_writable($databasefile)){
				if($fh = fopen($databasefile, 'a')){
					fwrite($fh, $implementation.';'.$value."\n");
					fclose($fh);
				}
			}
		}
	}
}

function isindatabase($databasefile, $implementation, $value){
	$database = file($databasefile);

	foreach($database as $entry){
		if($implementation.';'.$value == rtrim($entry)){
			return 1;
		}
	}

	return 0;
}

function findmatchindatabase($databasefile, $fingerprint){
	$database = file($databasefile);

	foreach($database as $entry){
		$entryarray = explode(';', $entry, 2);
		if($fingerprint == rtrim($entryarray['1'])){
			$matches.= $entryarray['0'].';';
		}
	}

	return $matches;
}

// Announcement
function announcefingerprintmatches($fullmatchlist, $mode='besthit', $hitpossibilities=0){
	$resultarray = explode("\n", $fullmatchlist);

	foreach($resultarray as $result){
		$entry = explode('=', $result, 2);

		if(strlen($entry['0'])){
			if($scan_besthitcount < $entry['1']){
				$scan_besthitname = $entry['0'];
				$scan_besthitcount = $entry['1'];
			}
			$scan_resultlist.= $entry['0'].': '.$entry['1']."\n";
			$scan_resultarray[] = $entry['1'].';'.htmlspecialchars($entry['0']);
		}
	}

	if($mode == 'list'){
		return $scan_resultlist;
	}elseif($mode == 'besthitlist'){
		rsort($scan_resultarray);
		for($i=0; $i<10; ++$i){
			$scan_resultitem = explode(';', $scan_resultarray[$i], 2);
			if($scan_resultitem['0'] > 0){
				if($hitpossibilities > 0){
					$scan_hitaccuracy = round((100 / $hitpossibilities) * $scan_resultitem['0'], 2);
				}else{
					$scan_hitaccuracy = round((100 / $scan_besthitcount) * $scan_resultitem['0'], 2);
				}

				$scan_hitlist.= ($i+1).'. '.$scan_resultitem['1'].' ('.$scan_hitaccuracy. '% with '.$scan_resultitem['0'].' hits)';
	
				if($i<9){
					$scan_hitlist.= "\n";
				}
			}
		}

		return $scan_hitlist;
	}elseif($mode == 'besthitdetail'){
		if($hitpossibilities > 0){
			$scan_hitaccuracy = round((100 / $hitpossibilities) * $scan_besthitcount, 2);
		}else{
			$scan_hitaccuracy = 100;
		}
		return $scan_besthitname.' ('.$scan_hitaccuracy. '% with '.$scan_besthitcount.' hits)';
	}else{
		return $scan_besthitname;
	}
}

function generatematchstatistics($matchlist){
	$matchesarray = explode(';', $matchlist);
	$matches = array_unique($matchesarray);
	
	foreach($matches as $match){
		$matchstatistic.= $match.'='.countif($matchesarray, $match)."\n";
	}

	return $matchstatistic;
}

function countif($input, $search){
	foreach($input as $entry){
		if($entry == $search){
			++$sum;
		}
	}
	return $sum;
}

// Save Fingerprints
function sendfingerprint($implementation, $fingerprint, $details=''){
	$mailmessage = 'Implementation: '.$implementation."\n\n";
	if($details){
		$mailmessage.= $details."\n\n";
	}
	$mailmessage.= $fingerprint."\n";
	mail('marc.ruef@computec.ch', '[browserrecon] fingerprint upload', $mailmessage);
}

function saveallfingerprintstodatabase($rawheader, $implementation){
	savenewfingerprinttodatabase('scan/user-agent.fdb', $implementation, getheadervalue($rawheader, 'User-Agent'));
	savenewfingerprinttodatabase('scan/accept.fdb', $implementation, getheadervalue($rawheader, 'Accept'));
	savenewfingerprinttodatabase('scan/accept-language.fdb', $implementation, getheadervalue($rawheader, 'Accept-Language'));
	savenewfingerprinttodatabase('scan/accept-encoding.fdb', $implementation, getheadervalue($rawheader, 'Accept-Encoding'));
	savenewfingerprinttodatabase('scan/accept-charset.fdb', $implementation, getheadervalue($rawheader, 'Accept-Charset'));
	savenewfingerprinttodatabase('scan/keep-alive.fdb', $implementation, getheadervalue($rawheader, 'Keep-Alive'));
	savenewfingerprinttodatabase('scan/connection.fdb', $implementation, getheadervalue($rawheader, 'Connection'));
	savenewfingerprinttodatabase('scan/cache-control.fdb', $implementation, getheadervalue($rawheader, 'Cache-Control'));
	savenewfingerprinttodatabase('scan/ua-pixels.fdb', $implementation, getheadervalue($rawheader, 'UA-Pixels'));
	savenewfingerprinttodatabase('scan/ua-color.fdb', $implementation, getheadervalue($rawheader, 'UA-Color'));
	savenewfingerprinttodatabase('scan/ua-os.fdb', $implementation, getheadervalue($rawheader, 'UA-OS'));
	savenewfingerprinttodatabase('scan/ua-cpu.fdb', $implementation, getheadervalue($rawheader, 'UA-CPU'));
	savenewfingerprinttodatabase('scan/te.fdb', $implementation, getheadervalue($rawheader, 'TE'));
	savenewfingerprinttodatabase('scan/header-order.fdb', $implementation, getheaderorder($rawheader));
}

function savenewfingerprinttodatabase($filename, $implementation, $value){
	addtodatabase($filename, $implementation, $value);
}

// Additional Analysis Modules
function usedproxy($request){
	if(strpos($request, 'Via:') === FALSE){
		return 0;
	}else{
		return 1;
	}
}

function identifyproxy($request){
	if(usedproxy($request)){
		$via = getheadervalue($request, 'Via');
		$for = getheadervalue($request, 'X-Forwarded-For');

		if(strpos($request, 'X-BlueCoat-Via:') !== FALSE){
			$product = 'Bluecoat';
			$product_information = getheadervalue($request, 'X-BlueCoat-Via');
		}elseif(stripos($request, 'ISA') !== FALSE){
			$product = 'Microsoft ISA';
			$product_information = 'none';
		}elseif(stripos($request, 'IWSS') !== FALSE){
			$product = 'Trend Micro InterScan Web Security Suite (IWSS)';
			$product_information = 'none';
		}elseif(stripos($request, 'NetCache') !== FALSE){
			$product = 'NetCache NetApp';
			$product_information = 'none';
		}elseif(stripos($request, 'squid') !== FALSE){
			$product = 'Squid Proxy';
			$product_information = 'none';
		}else{
			$product = 'unknown';
			$product_information = 'none';
		}

		return 'Proxy used (For: '.$for.', Via: '.$via.', Product: '.$product.', Details: '.$product_information.')';
	}else{
		return 'no proxy used';
	}
}

?>
