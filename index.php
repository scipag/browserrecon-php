<?php

// Include the browserrecon application
include('inc_browserrecon.php');

// Do the web browser fingerprinting
$browser = browserrecon(getfullheaders());

if($_SERVER['QUERY_STRING'] == 'pic'){
	$font = 2;
	$width  = imagefontwidth($font) * strlen($browser);
	$height = imagefontheight($font);
	$im = imagecreate($width, $height);

	$x = imagesx($im) - $width ;
	$y = imagesy($im) - $height;
	$background_color = imagecolorallocate($im, 242, 242, 242);
	$text_color = imagecolorallocate($im, 0, 0, 0);
	$trans_color = $background_color;
	imagecolortransparent($im, $trans_color);
	imagestring($im, $font, $x, $y,  $browser, $text_color);

	if(function_exists('imagegif')){
		header('Content-type: image/gif');
		imagegif($im);
	}elseif (function_exists('imagejpeg')){
		header('Content-type: image/jpeg');
		imagejpeg($im, '', 0.5);
	}elseif(function_exists('imagepng')){
		header('Content-type: image/png');
		imagepng($im);
	}
	imagedestroy($im);
}else{
	echo $browser;
}

?>
