<?php

// Configuration

$ipv6_schema=1;

$address='localhost';
$user='nufwuser';
$password='nufwpasswd';
$database='nufwdb';
$ssl=0;
$cacert=NULL;

$netmask_check=1;	/* WARNING: if you set this and ipv6_schema is 1 then
					 * you must have declared 'check_net' function. */

// Assertions

require_once('pages/authentication.php');
require_once('pages/authentication_error.php');
require_once('pages/authentication_success.php');

// Utility Functions

function MySQL_is_ipv4($ip)
{
	if ( $ip==long2ip(ip2long($ip)))
		return 1;
	else
		return 0;
}

function MySQL_ip2sql($ip)
{
	global $ipv6_schema;
	if ( $ipv6_schema ) {
		if ( MySQL_is_ipv4($ip) )
			$ip= "::ffff:".$ip;
		$ip=unpack("H32", inet_pton($ip));
		$ip = "0x".$ip[1];
	} else {
		$ip = sprintf("%u",ip2long(preg_replace("/\s+/","",$ip)));
	}
	return $ip;
}

// Main


// Connect to MySQL database
if(!extension_loaded('mysqli')) 
{
	if (preg_match('/windows/i', getenv('OS'))) 
	{
		if(FALSE==dl('php_mysqli.dll'))
			return -1;
	}
	else 
	{
		if(FALSE==dl('mysqli.so'))
			return -1;
	}
}

$MySQL_fd = mysqli_init();

if ($ssl && !$MySQL_fd->ssl_set(NULL,NULL,$cacert,NULL,NULL))
	return -1;
if ( !$MySQL_fd->real_connect($address,$user,$password,$database) )
	return -1;

// is user connected?
if ($netmask_check) { // with netmask check
	if ($ipv6_schema)
		$query="SELECT user_id,username,no_logout FROM ipauth_sessions WHERE check_net(ip_saddr, ".MySQL_ip2sql($_SERVER['REMOTE_ADDR']).", netmask) AND (end_time is NULL OR end_time > NOW()) LIMIT 1;";
	else
		$query="SELECT user_id,username,no_logout FROM ipauth_sessions WHERE ip_saddr = (".MySQL_ip2sql($_SERVER['REMOTE_ADDR'])." & netmask) AND (end_time is NULL OR end_time > NOW()) LIMIT 1;";
} else // without netmask check
	$query="SELECT user_id,username,no_logout FROM ipauth_sessions WHERE ip_saddr=".MySQL_ip2sql($_SERVER['REMOTE_ADDR'])." LIMIT 1;";
	
$res=$MySQL_fd->query($query);
	
$userinfo=$res->fetch_row();
if($userinfo!=NULL)
{
	// Connected User
	if (isset($_GET['logout']) && $userinfo[2]=="n")
	{
		// User wants to log out
		// Disconnect user
		$res=$MySQL_fd->query("DELETE FROM ipauth_sessions WHERE user_id=".$userinfo[0]." and ip_saddr=".MySQL_ip2sql($_SERVER['REMOTE_ADDR']).";");
		$res=$MySQL_fd->query("UPDATE users SET end_time=NOW() WHERE user_id=".$userinfo[0]." and ip_saddr=".MySQL_ip2sql($_SERVER['REMOTE_ADDR']).";");
		Util_PrintAuthentication();
	}
	else
	{
		// User in connected mode
		Util_PrintAuthenticationSuccess($userinfo[1],$userinfo[2]=="n" ? 1 : 0);
	}
}
else
{
	// Anonymous User
	if (isset($_POST['login']))
	{
		// User want to log in
		// Authenticate user
		$res=$MySQL_fd->query("SELECT uid FROM userinfo WHERE username='".$MySQL_fd->real_escape_string($_POST['username'])."' AND password=PASSWORD('".$MySQL_fd->real_escape_string($_POST['password'])."') LIMIT 1;");
		$row=$res->fetch_row();
		if($row!=NULL)
		{
			// User Login
			// Account user
			$res=$MySQL_fd->query("INSERT INTO ipauth_sessions(user_id,username,ip_saddr,start_time,end_time) VALUES(".$row[0].",'".$MySQL_fd->real_escape_string($_POST['username'])."',".MySQL_ip2sql($_SERVER['REMOTE_ADDR']).",NOW(),NULL);");
			$res=$MySQL_fd->query("INSERT INTO users(user_id,username,ip_saddr,start_time,end_time) VALUES(".$row[0].",'".$MySQL_fd->real_escape_string($_POST['username'])."',".MySQL_ip2sql($_SERVER['REMOTE_ADDR']).",NOW(),NULL);");
			Util_PrintAuthenticationSuccess($_POST['username'],0);
		}
		else
		{
			// Login Error
			Util_PrintAuthenticationError();
		}
	}
	else
	{
		// Anonymous
		Util_PrintAuthentication();
	}
}
$MySQL_fd->close();
?>
