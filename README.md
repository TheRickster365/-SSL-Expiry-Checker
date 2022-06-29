# SSL-Expiry-Checker
A one page PHP (+ config) script to check your SSL certificates.

This was inspired by https://github.com/PalFed/SSL-Expiry-Checker

I added the ability to sort by the days left and to query a non standard ssl port eg https://www.foo.com:8443

Added support to query certificate on smtp server port 25

Supported Ports (I have tested against)<br>
SMTP 25 465 587<br>
POP3S 995<br>
IMAP  143<br>
IMAPS 993<br>
HTTPS 443 (Other eg 8744)<br>


# Installation
Put on your webserver, copy the sslChecker.sample.ini.php file to sslChecker.ini.php, modify to suit your needs and view.

# Example Screenshot
![Screenshot](https://raw.githubusercontent.com/TheRickster365/SSL-Expiry-Checker/master/SSL-Expiry-Checker-Screenshot.JPG)
