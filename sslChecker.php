<?php
/*-----------------------------------------------------------------------------*/
function GetConfig() {
global $config;

if (file_exists(__DIR__."/sslChecker.ini.php")) {
	$config=parse_ini_file(__DIR__."/sslChecker.ini.php");
    return true;
}
else {
	print("Error: ".__DIR__."/sslChecker.ini.php not found");
    return false;
}
}
/*-----------------------------------------------------------------------------*/

function debug ($val) {

echo '<pre>';print_r($val);echo '</pre>';
}
/*-----------------------------------------------------------------------------*/

function pagehead() {

$now = date("r");

echo "<html>";
print <<<END
<head>
<!-- Refresh page every day -->
<meta http-equiv="refresh" content="86400" />
<title>SSl Checker</title>
    <style>
        thead, .th {border: 1px solid black;font-weight: bold;}
        .error  {background: purple; color: white;}
        .warn {background: orange;}
        .expired  {background: red; color: white;}
        .ok {background: lightgreen;}
	body {background-color: #ffffff; color: #000000;}
	body, td, th, h1, h2 {font-family: sans-serif;}
	pre {margin: 0px; font-family: monospace;}
	a:link {color: #000099; text-decoration: none; background-color: #ffffff;}
	a:hover {text-decoration: underline;}
	table {border-collapse: collapse;}
	.center {text-align: center;}
	.center table { margin-left: auto; margin-right: auto; text-align: left;}
	.center th { text-align: center !important; }
	td, th { border: 1px solid #000000; font-size: 90%; vertical-align: baseline;}
	h1 {font-size: 150%;}
	h2 {font-size: 75%;}
	.p {text-align: left;}
	.e {background-color: #ccccff; font-weight: bold; color: #000000;}
	.h {background-color: #9999cc; font-weight: bold; color: #000000;}
	.v {background-color: #cccccc; color: #000000;}
	.vr {background-color: #cccccc; text-align: right; color: #000000;}
	img {float: right; border: 0px;}
	hr {width: 600px; background-color: #cccccc; border: 0px; height: 1px; color: #000000;} 
    </style>
</head>
<body>
    <h1>SSL Expiry Checker</h1>
    <h2>$now</h2>
END;
}
/*-----------------------------------------------------------------------------*/

function pagefoot() {

print <<<END
</body>
END;
echo "</html>";
}
/*-----------------------------------------------------------------------------*/

function legend() {

print <<<END
<br/>
<table  cellspacing="1" cellpadding="3">
<tr><td class="th"> Legend </td>
<td class="ok"> OK </td>
<td class="warn"> Warning </td>
<td class="expired"> Expired </td>
<td class="error"> Error </td>
</tr>
</tbody>
</table>
END;
}

/*-----------------------------------------------------------------------------*/

function tablehead() {

print <<<END
<table  cellspacing="1" cellpadding="3">
<thead>
<tr>
<td> Domain </td>
<td> Links </td>
<td> Valid From </td> 
<td> Expiry Date </td>
<td> Days  Valid</td>
<td> Days Left </td>
<td> CN </td>
<td> Issuer </td>
<td> AltName </td>
</tr>
</thead>
<tbody>
END;
}
/*-----------------------------------------------------------------------------*/

function tablerow($data) {
global $config;

$warnDays = $config['warnDays'];
$dateFormat = $config['dateFormat'];

$Domain = $data['domain'];
$validFrom = date($dateFormat, $data['from']);
$validTo = date($dateFormat, $data['to']);

$CN = $data['cn'];
$Issuer = $data['issuer'];
$SubjectAltName = $data['altname'];

$DaysValid = $data['valid'];
$DaysLeft = $data['expire'];


if ($DaysLeft <= -19160) $class = "error";
else if ($DaysLeft < 0) $class="expired";
else if ($DaysLeft < $warnDays) $class="warn";
else $class="ok";


print <<<END
<tr class="$class">
<td>$Domain</a></td>
<td><a href=http://$Domain target=“_blank”>http</a>  <a href=https://$Domain target=“_blank”>https</a></td>
<td>$validFrom</td>
<td>$validTo</td>
<td>$DaysValid</td>
<td>$DaysLeft</td>
<td>$CN</td>
<td>$Issuer</td>
<td>$SubjectAltName</td>
</tr>
END;
}

/*-----------------------------------------------------------------------------*/
function tablefoot() {
print <<<END

</tbody>
</table>
END;
}
/*-----------------------------------------------------------------------------*/
function getHTTPSCertInfo($Domain,$Port) {

$url = "https://".$Domain;
$orignal_parse = parse_url($url, PHP_URL_HOST);
$get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
$read = stream_socket_client("ssl://".$orignal_parse.":".$Port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
$cert = stream_context_get_params($read);
$certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);


return $certinfo;
}
/*-----------------------------------------------------------------------------*/
//https://stackoverflow.com/questions/13402866/how-do-i-verify-a-tls-smtp-certificate-is-valid-in-php
/*-----------------------------------------------------------------------------*/
function GetSMTPCertInfo ($Domain,$Port) {
$myself   = "my_server.example.com"; // Who I am
$cabundle = '/etc/ssl/cacert.pem';   // Where my root certificates are

$smtp = fsockopen( "tcp://{$Domain}", $Port, $errno, $errstr );
fread( $smtp, 512 );
 
fwrite($smtp,"HELO {$myself}\r\n");
fread($smtp, 512);
 
// Switch to TLS
fwrite($smtp,"STARTTLS\r\n");
fread($smtp, 512);
stream_set_blocking($smtp, true);
//stream_context_set_option($smtp, 'ssl', 'verify_peer', true);
//stream_context_set_option($smtp, 'ssl', 'allow_self_signed', false);
 stream_context_set_option($smtp, 'ssl', 'capture_peer_cert', true);
//stream_context_set_option($smtp, 'ssl', 'cafile', $cabundle);
$secure = stream_socket_enable_crypto($smtp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
stream_set_blocking($smtp, false);
$opts = stream_context_get_options($smtp);

$certinfo = openssl_x509_parse($opts['ssl']['peer_certificate']);
 
return $certinfo;
}
/*-----------------------------------------------------------------------------*/
function GetIMAPCertInfo ($Domain,$Port) {

$smtp = fsockopen( "tcp://{$Domain}", $Port, $errno, $errstr );
fread( $smtp, 512 );
 
// Switch to TLS
fwrite($smtp,"A1 STARTTLS\r\n");
fread($smtp, 512);
stream_set_blocking($smtp, true);
//stream_context_set_option($smtp, 'ssl', 'verify_peer', true);
//stream_context_set_option($smtp, 'ssl', 'allow_self_signed', false);
 stream_context_set_option($smtp, 'ssl', 'capture_peer_cert', true);
//stream_context_set_option($smtp, 'ssl', 'cafile', $cabundle);
$secure = stream_socket_enable_crypto($smtp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
stream_set_blocking($smtp, false);
$opts = stream_context_get_options($smtp);

$certinfo = openssl_x509_parse($opts['ssl']['peer_certificate']);
 
return $certinfo;
}
/*-----------------------------------------------------------------------------*/
/* Needed for PHP < 5.5.0
*/
function array_column_manual($array, $column)  {
$newarr = array();
foreach ($array as $row) 
    $newarr[] = $row[$column];

return $newarr;
}
/*-----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------*/
pagehead();
$config;
if (GetConfig () == true){
    $count=0;
    $data;
    $now = time();

    //Get Certificate details for each Domain
    foreach ($config['domains'] as $domain) {

        $pieces = explode(":", $domain);
        $dom = $pieces[0];
        $port = "443";
        if (isset ($pieces[1]))
	    $port = $pieces[1];

		switch ($port){
				case 25:
				case 587:
				$certinfo = getSMTPCertInfo($dom,$port);
				break;
				
				case 143:
				GetIMAPCertInfo ($dom,$port);
				break;
			
			default:
            $certinfo = getHTTPSCertInfo($dom,$port);
			break;
		}

        $certdata[$count]['domain'] = $domain;
        $certdata[$count]['from'] = $certinfo['validFrom_time_t'];
        $certdata[$count]['to'] = $certinfo['validTo_time_t'];
        $certdata[$count]['valid'] = floor(($certinfo['validTo_time_t'] - $certinfo['validFrom_time_t'])/(3600*24));
        $certdata[$count]['expire'] = floor(($certinfo['validTo_time_t'] - $now)/(3600*24));
        $certdata[$count]['cn'] = $certinfo['subject']['CN'];
        $certdata[$count]['issuer'] = $certinfo['issuer']['O'];
        $certdata[$count]['altname'] = $certinfo['extensions']['subjectAltName'];

        $count += 1;
    
    }

    //Sort Array on Days Left
    $expire  = array_column_manual($certdata, 'expire');
    array_multisort ($expire,SORT_ASC,$certdata);

    //Output Table
    tablehead();

    foreach ($certdata as $data) {
        tablerow($data);
    }

    tablefoot();
    legend();
}
pagefoot();
//debug($certdata);
//phpinfo();
?>
