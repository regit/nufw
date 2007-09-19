<?php
/****************************************************************************
 * Util_PrintLoginSuccessfull                                               *
 ****************************************************************************
 *                                                                          *
 * Print Login Confirmation screen                                          *
 *                                                                          *
 ***************************************************************************/

function Util_PrintAuthenticationSuccess($username,$can_logout)
{
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Log In Successfull</title>
<style type="text/css">
<!--
.Style1 {	font-family: "Century Gothic";
	font-size: 24px;
}
.Style6 {
	font-size: 14px;
	font-family: "Century Gothic";
}
-->
</style>
</head>

<body>
<table width="760" border="1" align="center" cellpadding="0" cellspacing="0" bordercolor="#CCCCCC" bordercolorlight="" bordercolordark="" bgcolor="#FFFFFF">
  <tr>
    <th height="454" valign="top" scope="col"><table width="760" height="375" border="0" align="center" cellpadding="0" cellspacing="0" bordercolor="" bordercolorlight="" bordercolordark="">
      <tr>
        <th height="96" align="left" valign="top"><img src="images/nupik.png" height="140" /></th>
        </tr>
      <tr>
        <th ><h1 class="Style1" style="margin-top:2em;">Welcome <?php echo $username; ?><br/></h1>
	<?php
		if($can_logout)
		{
?>
	<div align=center><a href="<?php echo (isset($_SERVER['HTTPS']) ? "https://" : "http://").$_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'].$_SERVER['PHP_SELF'] ?>?logout=me">LogOut</a></div>
<?php
		}
?>
<?php
	/*
		See comment in authentication.php
?>
            <span class="Style6">Click to continue </span>: <a href="<?php echo $_POST['orig_dest_url'];?>"><?php echo $_POST['orig_dest_url'];?></a></th>
<?php
	*/
?>
      </tr>
      <tr>
      </tr>
      <tr><td>&nbsp;</tr>
    </table></th>
  </tr>
</table>
<br />
</body>
</html>
<?php
}
?>
