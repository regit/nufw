<?php
# Copyright 2007, INL
# Written by Eric Leblond <eric@inl.fr>
# $Id$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
#  This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
?>
<html>
<head>
<title>NuFW IP auth page</title>
</head>
<body>

<H1>NuFW IP auth page</H1>
<?php

$link = mysql_connect("localhost","root","");
if ($link != 0) {
	if (mysql_select_db("nulog", $link) == 0) {
		die("Can't select database");
	}
} else {
	die("Can't connect to db");
}

$straddr = $_SERVER['REMOTE_ADDR'];
$ipaddr = pack("N4",0,0,0xffff,ip2long($straddr));

$query = "SELECT username FROM ipauth_sessions WHERE ip_saddr='".$ipaddr."'";
$result = mysql_query($query) or die("Query missed");
if (mysql_num_rows($result) > 0) {
	$button_label = "Disconnect";
	$button_value = 1;
} else {
	$button_label = "Connect";
	$button_value = 0;
}

$action_ok = FALSE;
$username = "";

if (array_key_exists("user",$_POST)) {
	/* do select to check password */
	if (! array_key_exists("password",$_POST)) {
		die("No password provided");
	}
	$username = mysql_real_escape_string($_POST['user']);
	$password = mysql_real_escape_string($_POST['password']);

	$query = "SELECT username FROM userinfo WHERE username='$username' AND password=PASSWORD('$password')";
	$result = mysql_query($query) or die("Query missed");
	if (mysql_num_rows($result) == 1) {
		$action_ok = TRUE;
	} else {
		die("Bad guy, get out");
	}
}

if ($action_ok == TRUE and array_key_exists("sub", $_POST)) {
	echo "Operation in progress<br>";
	if ($_POST["sub"] == 1) {
		echo "Deleting information from Database<br>";
		$query = "DELETE FROM ipauth_sessions WHERE username='$username' AND ip_saddr='$ipaddr'";
		$result = mysql_query($query) or die("Diconnect Query missed");
		$button_label = "Connect";
		$button_value = 0;
	} else {
		echo "Inserting information to Database<br>";
		$query = "INSERT INTO ipauth_sessions (ip_saddr, username) VALUES ('".$ipaddr."', '".$username."')";
		$result = mysql_query($query) or die("Connect Query missed");
		$button_label = "Disconnect";
		$button_value = 1;
	}
} 
?>

<form target=self method=post>
<p>
Username: <input type=text name="user" >
</p>
<p>
Password: <input type=password name="password">
</p>
<button type=submit name="sub" value="<?php echo $button_value; ?>" ><?php echo $button_label; ?></button>

</form>

</body>
</html>
