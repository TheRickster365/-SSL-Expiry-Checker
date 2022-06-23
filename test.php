<?php
 $server   = "webmail.ccoz.com";        // Who I connect to
 $myself   = "my_server.example.com"; // Who I am
 $cabundle = '/etc/ssl/cacert.pem';   // Where my root certificates are

 // Verify server. There's not much we can do, if we suppose that an attacker
 // has taken control of the DNS. The most we can hope for is that there will
 // be discrepancies between the expected responses to the following code and
 // the answers from the subverted DNS server.

 // To detect these discrepancies though, implies we knew the proper response
 // and saved it in the code. At that point we might as well save the IP, and
 // decouple from the DNS altogether.
/*
 $match1   = false;
     $addrs    = gethostbynamel($server);
     foreach($addrs as $addr)
     {
         $name = gethostbyaddr($addr);
         if ($name == $server)
         {
             $match1 = true;
             break;
         }
     }
     // Here we must decide what to do if $match1 is false.
     // Which may happen often and for legitimate reasons.
     print "Test 1: " . ($match1 ? "PASSED" : "FAILED") . "\n";
 
     $match2   = false;
     $domain   = explode('.', $server);
     array_shift($domain);
     $domain = implode('.', $domain);
     getmxrr($domain, $mxhosts);
     foreach($mxhosts as $mxhost)
     {
         $tests = gethostbynamel($mxhost);
         if (0 != count(array_intersect($addrs, $tests)))
         {
             // One of the instances of $server is a MX for its domain
             $match2 = true;
             break;
         }
     }
     // Again here we must decide what to do if $match2 is false.
     // Most small ISP pass test 2; very large ISPs and Google fail.
     print "Test 2: " . ($match2 ? "PASSED" : "FAILED") . "\n";
     // On the other hand, if you have a PASS on a server you use,
     // it's unlikely to become a FAIL anytime soon.
 
     // End of maybe-they-help-maybe-they-don't checks.
 
    echo "<br>here";
*/
     // Establish the connection on SMTP port 25
     $smtp = fsockopen( "tcp://{$server}", 25, $errno, $errstr );
     fread( $smtp, 512 );
 
     // Here you can check the usual banner from $server (or in general,
     // check whether it contains $server's domain name, or whether the
     // domain it advertises has $server among its MX's.
     // But yet again, Google fails both these tests.
 
     fwrite($smtp,"HELO {$myself}\r\n");
     fread($smtp, 512);
 
     // Switch to TLS
     fwrite($smtp,"STARTTLS\r\n");
     fread($smtp, 512);
     stream_set_blocking($smtp, true);
//     stream_context_set_option($smtp, 'ssl', 'verify_peer', true);
//     stream_context_set_option($smtp, 'ssl', 'allow_self_signed', false);
     stream_context_set_option($smtp, 'ssl', 'capture_peer_cert', true);
//     stream_context_set_option($smtp, 'ssl', 'cafile', $cabundle);
     $secure = stream_socket_enable_crypto($smtp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
     stream_set_blocking($smtp, false);
     $opts = stream_context_get_options($smtp);
     echo"<pre>";print_r($opts);echo"</pre>";     

     if (!isset($opts['ssl']['peer_certificate'])) {
         $secure = false;
     } else {
         $cert = openssl_x509_parse($opts['ssl']['peer_certificate']);
         echo"<pre>";print_r($cert);echo"</pre>";
         
     }
 
     if (!$secure) {
             die("failed to connect securely\n");
     }
