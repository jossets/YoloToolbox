var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())
 
app.get('/', function(req, res) {
 if (req.cookies.profile) {
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) { 
     var sum = eval(obj.num + obj.num);
     res.send("Hey " + obj.username + " " + obj.num + " + " + obj.num + " is " + sum);
   }else{
     res.send("An error occurred...invalid username type"); 
   }
}else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ==", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("<h1>404</h1>");
});
app.listen(3000);

var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())
 
app.get('/', function(req, res) {
 if (req.cookies.profile) {
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) { 
     var sum = eval(obj.num + obj.num);
     res.send("Hey " + obj.username + " " + obj.num + " + " + obj.num + " is " + sum);
   }else{
     res.send("An error occurred...invalid username type"); 
   }
}else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ==", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("<h1>404</h1>");
});
app.listen(3000);
