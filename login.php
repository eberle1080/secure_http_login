<?php

// Author: Chris Eberle <eberle1080@gmail.com>
//
// A very VERY simple proof of concept for a secure login page that doesn't require https
// SHOULD be safe from (naive) man in the middle attacks. YMMV.

//////////////////////////////////////////////////////////////////////////////
// Configuration section

// Users array
// Format:
//
// $user_db = array(
//   uid => array(login, name, pass),
//   uid => array(login, name, pass)
// );
//
// uid and login must both be unique.
// To make a password for a user, just run:
//   $> echo -n 'password' | sha1sum

$user_db = array(
    '1' => array('test',  'Test user 1', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'), // pass is 'test'
    '2' => array('test2', 'Test user 2', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3')  // pass is 'test'
);

// set timeout period in seconds
$inactive = 10 * 60; // 10 minutes

//////////////////////////////////////////////////////////////////////////////
// Login handling stuff

session_start();

function truncate($string, $max = 20, $replacement = '')
{
    if (strlen($string) <= $max)
    {
        return $string;
    }
    $leave = $max - strlen ($replacement);
    return substr_replace($string, $replacement, $leave);
}

// one task of the server is to provide random values to hash with
if($_GET['task']=='getseed')
{
    unset($_SESSION['seed']);
    unset($_SESSION['logged_in']);
    unset($_SESSION['user_id']);

    if(isset($_SESSION['seed']))
    {
        $seed = $_SESSION['seed'];
    }
    else
    {
        $seed = truncate("" + (time() * rand(1,15)), 10);
        $_SESSION['seed'] = $seed;
    }

    echo $seed;
    die();
}
else if($_GET['task'] == 'checklogin')
{
    unset($_SESSION['logged_in']);
    unset($_SESSION['user_id']);

    if(!isset($_SESSION['seed']))
    {
        die('false|No seed.');
    }

    $user = $_GET['username'];
    $hash = $_GET['hash'];
    $passhash = "";
    $tmpid = -1;

    foreach($user_db as $id => $value)
    {
        if($value[0] == $user)
        {
            $passhash = $value[2];
            $tmpid = $id;
            break;
        }
    }

    if($passhash == "")
        die('false|Invalid username or password.');

    $newhash = sha1($passhash . $_SESSION['seed']);

    if($newhash == $hash)
    {
        unset($_SESSION['seed']);
        $_SESSION['logged_in'] = true;
        $_SESSION['user_id'] = $tmpid;
        die('true|Success');
    }
    else
    {
        die('false|Invalid username or password.');
    }
}
else if($_GET['task'] == 'logout')
{
    unset($_SESSION['seed']);
    unset($_SESSION['logged_in']);
    unset($_SESSION['user_id']);
}

$valid = false;
if(!isset($_GET['task']))
{
    if(isset($_SESSION['logged_in']))
    {
        if(isset($_SESSION['user_id']))
        {
            $id = $_SESSION['user_id'];
            if(isset($user_db[$id]))
                $valid = true;
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// Decide whether or not they get the login page

if($valid == false)
{
    showLoginPage();
}
else
{
    // check to see if $_SESSION['timeout'] is set
    if(isset($_SESSION['timeout']))
    {
        $session_life = time() - $_SESSION['timeout'];
        if($session_life > $inactive)
        {
            session_destroy();
            header("Location: " . $_SERVER['PHP_SELF'] . "?msg=timeout");
            die();
        }
    }
    $_SESSION['timeout'] = time();
    showMainPage();
}

//////////////////////////////////////////////////////////////////////////////
// Show the login page

function showLoginPage()
{
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Log in</title>
<script type="text/javascript">
// method that sets up a cross-browser XMLHttpRequest object

var http = getHTTPObject();
var hasSeed = false;
var loggedIn = false;
var seed_id = 0;
var seed = 0;
var NORMAL_STATE = 4;
var PAGE = '<?php echo $_SERVER['PHP_SELF']; ?>';
var LOGIN_PREFIX = PAGE + '?';

// getSeed method:  gets a seed from the server for this transaction
function getSeed() 
{
  // only get a seed if we're not logged in and we don't already have one
  if(!loggedIn && !hasSeed) {
    // open up the path
    http.open('GET', LOGIN_PREFIX + 'task=getseed', true);
    http.onreadystatechange = handleHttpGetSeed;
    http.send(null);
  }
}

// handleHttpGetSeed method: called when the seed is returned from the server
function handleHttpGetSeed()
{
  // if there hasn't been any errors
  if (http.readyState == NORMAL_STATE) {
    // seed is the second element
    results = http.responseText.split('|');
    if(results[0] == "false" || results[0] == "true")
    {
      if(results[0] == "false")
      {
        err = document.getElementById('errors');
        err.innerHTML = results[1];
      }
      else
      {
        hasSeed = false;
        loggedIn = true;
        fullname = results[1];
        messages = '';
        window.location = PAGE;
      }

      btn = document.getElementById('btn_login');
      btn.disabled = false;

      return;
    }

    seed = http.responseText;

    // now we have the seed
    hasSeed = true;

    validateLogin();
  }
}

// validateLogin method: validates a login request
function validateLogin()
{
  // ignore request if we are already logged in
  if(loggedIn)
    return;

  

  if(hasSeed == false)
  {
    getSeed();
    return;
  }

  btn = document.getElementById('btn_login');
  err = document.getElementById('errors');
  err.innerHTML = "&nbsp;";

  // get form form elements 'username' and 'password'
  username = document.getElementById('username').value;
  password = document.getElementById('password').value;

  // ignore if either is empty
  if(username != '' && password  != '') {
    // compute the hash of the hash of the password and the seed
    hash = sha1Hash(sha1Hash(password) + seed);
    btn.disabled = true;

    // open the http connection
    http.open('GET', LOGIN_PREFIX + 'task=checklogin&username='+username+'&id='+seed_id+'&hash='+hash, true);

    // where to go
    http.onreadystatechange = handleHttpValidateLogin;
    http.send(null);
  }
  else
  {
    err.innerHTML = "Please enter a username and password.";
  }
}

// handleHttpValidateLogin method: called when the validation results are returned from the server
function handleHttpValidateLogin()
{
  // did the connection work?
  if (http.readyState == NORMAL_STATE) {
    // split by the pipe
    results = http.responseText.split('|');
    if (results[0] == 'true')
    {
      hasSeed = false;
      loggedIn = true;
      fullname = results[1];
      messages = '';
      window.location = PAGE;
    }
    else
    {
      messages = results[1];
      if(messages == "No seed.")
      {
        hasSeed = false;
        getSeed();
      }
      else
      {
        err = document.getElementById('errors');
        err.innerHTML = messages;
      }
    }
    btn = document.getElementById('btn_login');
    btn.disabled = false;
  }
}

// resetLogin method: if logged in, 'logs out' and allows a different user/pass to be entered
function resetLogin()
{
  loggedIn = false;
  hasSeed = false;
}

function sha1Hash(msg)
{
  // constants [4.2.1]
  var K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];


  // PREPROCESSING
  msg += String.fromCharCode(0x80); // add trailing '1' bit to string [5.1.1]

  // convert string msg into 512-bit/16-integer blocks arrays of ints [5.2.1]
  var l = Math.ceil(msg.length/4) + 2;  // long enough to contain msg plus 2-word length
  var N = Math.ceil(l/16);              // in N 16-int blocks
  var M = new Array(N);
  for (var i=0; i<N; i++) {
    M[i] = new Array(16);
    for(var j=0; j<16; j++) {  // encode 4 chars per integer, big-endian encoding
      M[i][j] = (msg.charCodeAt(i*64+j*4)<<24) | (msg.charCodeAt(i*64+j*4+1)<<16) | 
                (msg.charCodeAt(i*64+j*4+2)<<8) | (msg.charCodeAt(i*64+j*4+3));
    }
  }

  // add length (in bits) into final pair of 32-bit integers (big-endian) [5.1.1]
  // note: most significant word would be ((len-1)*8 >>> 32, but since JS converts
  // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
  M[N-1][14] = ((msg.length-1)*8) / Math.pow(2, 32); M[N-1][14] = Math.floor(M[N-1][14])
  M[N-1][15] = ((msg.length-1)*8) & 0xffffffff;

  // set initial hash value [5.3.1]
  var H0 = 0x67452301;
  var H1 = 0xefcdab89;
  var H2 = 0x98badcfe;
  var H3 = 0x10325476;
  var H4 = 0xc3d2e1f0;

  // HASH COMPUTATION [6.1.2]

  var W = new Array(80); var a, b, c, d, e;
  for (var i=0; i<N; i++) {

    // 1 - prepare message schedule 'W'
    for(var t=0;  t<16; t++) W[t] = M[i][t];
    for(var t=16; t<80; t++) W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);

    // 2 - initialise five working variables a, b, c, d, e with previous hash value
    a = H0; b = H1; c = H2; d = H3; e = H4;

    // 3 - main loop
    for(var t=0; t<80; t++) {
      var s = Math.floor(t/20); // seq for blocks of 'f' functions and 'K' constants
      var T = (ROTL(a,5) + f(s,b,c,d) + e + K[s] + W[t]) & 0xffffffff;
      e = d;
      d = c;
      c = ROTL(b, 30);
      b = a;
      a = T;
    }

    // 4 - compute the new intermediate hash value
    H0 = (H0+a) & 0xffffffff;  // note 'addition modulo 2^32'
    H1 = (H1+b) & 0xffffffff; 
    H2 = (H2+c) & 0xffffffff; 
    H3 = (H3+d) & 0xffffffff; 
    H4 = (H4+e) & 0xffffffff;
  }

  return H0.toHexStr() + H1.toHexStr() + H2.toHexStr() + H3.toHexStr() + H4.toHexStr();
}

// function 'f' [4.1.1]
function f(s, x, y, z) 
{
  switch (s) {
  case 0: return (x & y) ^ (~x & z);           // Ch()
  case 1: return x ^ y ^ z;                    // Parity()
  case 2: return (x & y) ^ (x & z) ^ (y & z);  // Maj()
  case 3: return x ^ y ^ z;                    // Parity()
  }
}

// rotate left (circular left shift) value x by n positions [-3.2.5]
function ROTL(x, n)
{
  return (x<<n) | (x>>>(32-n));
}

// extend Number class with a tailored hex-string method 
//   (note toString(16) is implementation-dependant, and 
//   in IE returns signed numbers when used on full words)
Number.prototype.toHexStr = function()
{
  var s="", v;
  for (var i=7; i>=0; i--) { v = (this>>>(i*4)) & 0xf; s += v.toString(16); }
  return s;
}

function getHTTPObject() {
  var http_object;

  // MSIE Proprietary method
  /*@cc_on
  @if (@_jscript_version >= 5)
    try {
      http_object = new ActiveXObject("Msxml2.XMLHTTP");
    } catch (e) {
      try {
        http_object = new ActiveXObject("Microsoft.XMLHTTP");
      }
      catch (E) {
        http_object = false;
      }
    }
  @else
    xmlhttp = http_object;
  @end @*/

  // Mozilla and others method
  if(!http_object && typeof XMLHttpRequest != 'undefined') {
    try {
      http_object = new XMLHttpRequest();
    }
    catch (e) {
      http_object = false;
    }
  }

  return http_object;
}

function checkEnter(e){
  var characterCode;
  if(e && e.which){
    e = e;
    characterCode = e.which;
  }
  else {
    //e = event;
    characterCode = e.keyCode
  }

  if(characterCode == 13){ // enter
    validateLogin();
  }
  return true;
}

</script>
<style type="text/css">
  body {
    background-color: #101010;
    color: #ffffff;
  }

  h1 {
    text-align: center;
    color: #989898;
  }

  .login {
    background-color: #989898;
    border: 1px solid #D0D0D0;
    padding: 10px 30px;
    width: 320px;
    color: #000000;
    margin-left: auto;
    margin-right: auto;
  }

  label {
    display: block;
    margin-top: 10px;
  }

  #username {
    width: 100%;
    margin-left: 5px;
  }

  #password {
    width: 100%;
    margin-left: 5px;
  }

  #errors {
    color: #880000;
  }
</style>
</head>
<body>

<h1>Welcome, please log in</h1>
<div id="post_comment">
    <div class="login">
      <table border="0" padding="0" style="width: 100%;">
        <tr>
          <td style="width: 1%;">Username:</td>
          <td><input type="text" name="username" id="username" size="20" onkeypress="checkEnter(event);"></td>
        </tr>
        <tr>
          <td style="width: 1%;">Password:</td>
          <td><input type="password" name="password" id="password" size="20" onkeypress="checkEnter(event);"></td>
        </tr>
        <tr>
          <td colspan="2"><span id="errors"><?php
    if($_GET['msg'] == 'timeout')
        echo "Your session timed out, please log in.";
    else
        echo "&nbsp;";
?></span></td>
        </tr>
        <tr>
          <td colspan="2" style="text-align: right; padding-top: 15px;">
            <input type="button" value="Login" id="btn_login" onclick="validateLogin();">
          </td>
        </tr>
    </div>
</div>
</body>
</html>
<?php
}

//////////////////////////////////////////////////////////////////////////////
// Show the main page. Watch your globals.

function showMainPage()
{
    global $user_db;
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Main page</title>
<style type="text/css">
  body {
    background-color: #101010;
    color: #ffffff;
  }

  h1 {
    text-align: center;
    color: #989898;
  }

  a:link {color: #888888;}
  a:visited {color: #888888;}
  a:active {color: #C0C0C0;}
  a:hover {color: #E8E8E8;}
  a {text-decoration: none;}
</style>
</head>
<body>

<h1>Logged in!</h1>

<?php
    $user = $user_db[$_SESSION['user_id']];
    echo "Hello, " . $user[1] . ". ";
?>

You've logged in to the system. Congrats. If you want to do anything, too bad. If you want to log out,
<a href="<?php echo $_SERVER['PHP_SELF']; ?>?task=logout">click here</a>.

</body>
</html>
<?php
}
