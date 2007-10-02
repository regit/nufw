<?php
/****************************************************************************
 * Util_PrintAuthentication                                                 *
 ****************************************************************************
 *                                                                          *
 * Print Authentication screen, this is the first screen shown to the user  *
 *                                                                          *
 ***************************************************************************/

function Util_PrintAuthentication()
{
/*
	// To redirect the user after login completion (with Apache):
	$schema = "http".(isset($_GET['HTTPS'])?($_GET['HTTPS'] ==  "on" ? "s" : ""):"")."://";
	$orig_dest_url = str_replace('URL=', $schema, strstr(str_replace('%3f', '?',$_SERVER['QUERY_STRING']),'URL'));

	$orig_dest_ip = gethostbyname(strtok((isset($_GET['URL'])?$_GET['URL']:""), '/?'));
	$orig_dest_url_with_ip = preg_replace('/^(http:\/\/)([^\\\]*)\\/(.*)/', '${1}'.$orig_dest_ip.'/${3}', $orig_dest_url );
*/
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Authentication</title>
<style type="text/css">
<!--
.Style12 {font-size: 16px}
.Style15 {font-family: "Century Gothic"; font-size: 12px; }
.Style16 {font-family: "Century Gothic"; font-size: 16px;  font-weight: bold;}
.Style19 {
	font-family: "Century Gothic";
	font-size: 14px;
}
-->
</style>
</head>

<body>
<table width="760" border="1" align="center" cellpadding="0" cellspacing="0" bordercolor="#CCCCCC" bordercolorlight="" bordercolordark="" bgcolor="#FFFFFF">
  <tr>
    <th height="503" valign="top" scope="col"><table width="760" height="366" border="0" align="center" cellpadding="0" cellspacing="0" bordercolor="" bordercolorlight="" bordercolordark="">
      <tr>
        <th height="96" align="left" valign="top">Authentication</th>
        </tr>
      <tr>
        <th align="center" valign="top"><span class="Style12"><b>
          <br />
          <span class="Style19"><h1 class="Style19">
	  <?php echo (isset($_SERVER['URL'])?$_SERVER['URL']:""); ?>
	<span class="Style16">WELCOME!<br /><form action="<?php echo (isset($_SERVER['HTTPS']) ? "https://" : "http://").$_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'].$_SERVER['PHP_SELF'] ?>" method=post></span><br />
<?php
	/*
		See comment above.
?>
            <input type="hidden" name="orig_dest_url" value="<?php echo $orig_dest_url;?>" />
          <input type="hidden" name="orig_dest_ip" value="<?php echo $orig_dest_ip;?>" />
          <input type="hidden" name="orig_dest_url_with_ip" value="<?php echo $orig_dest_url_with_ip;?>" />
 <?php
	  */
?>
	  </h1>
            <table border="0" align="center" cellpadding="1" cellspacing="0" bgcolor="#ffffff">
              <tr valign="middle">
                <td width="61" align="right"><span class="Style15"> Username: </span></td>
                <td width="123" align="right"><input type="text" name="username" length="206" width="20" value="" />                </td>
              </tr>
              <tr valign="middle">
                <td align="right"><span class="Style15"> Password:</span></td>
                <td align="left"><input name="password" type="password" value="" width="20" length="206" />                </td>
              </tr>
              <tr valign="middle">
                <td colspan="2" align="center"><input name="login" type="submit" value="Send" />                </td>
              </tr>
	      </form>
          </table>
          <br /></th>
		<tr><td>
		<tr><td align=center>
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
