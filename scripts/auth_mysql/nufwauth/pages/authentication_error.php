<?php
/****************************************************************************
 * Util_PrintAuthError                                                      *
 ****************************************************************************
 *                                                                          *
 * Print Authentication Error screen                                        *
 *                                                                          *
 ***************************************************************************/

function Util_PrintAuthenticationError()
{
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Authentication Error</title>
<style type="text/css">
<!--
.Style13 {font-family: "Century Gothic"}
}
-->
</style>
</head>

<body>
<table width="760" border="1" align="center" cellpadding="0" cellspacing="0" bordercolor="#CCCCCC" bordercolorlight="" bordercolordark="" bgcolor="#FFFFFF">
  <tr>
    <th valign="top" scope="col"><table width="760" height="536" border="0" align="center" cellpadding="0" cellspacing="0" bordercolor="" bordercolorlight="" bordercolordark="">
      <tr>
        <th height="96" align="left" valign="top"><img src="images/nupik.png" height="140" /></th>
        </tr>
      <tr>
        <th height="176" ><h1 class="Style13">Authentication Error</h1>
          <p class="Style13">You entered wrong username or password.</p>
          <p class="Style13">Come <a href="javascript:history.go(-1)">back</a> and check your credentials</p>          </th>
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
