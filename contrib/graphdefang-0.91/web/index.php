<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<!-- 
#
# GraphDefang - a set of tools to create graphs of your mimedefang
#               spam and virus logs.
#
# Written by:    John Kirkland
#                jpk@bl.org
#
# Copyright (c) 2002-2003, John Kirkland
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#=============================================================================
-->

<?php
# CONFIGURE ME!!!
$OUTPUT_DIR = '/home/jpk/public_html/spam';
?>

<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title>GraphDefang</title>
</head>
<body>
<center>
<table border="0" width="50%">
<tr align="center">
  <td>
    <a href="index.php?view=hourly">Hourly</a>
  </td>
  <td>
    <a href="index.php?view=daily">Daily</a>
  </td>
  <td>
    <a href="index.php?view=monthly">Monthly</a>
  </td>
</tr>
</table>
<p />
<?php
$handle=opendir("$OUTPUT_DIR"); 
while ($filename = readdir($handle)) { 
	if ($filename != "." && $filename != ".." && $filename != "index.php" && $filename != ".index.php.swp") { 
		$filename_array[] = $filename;
	} 
}
closedir($handle); 

$view = $_GET['view'];
if (!$view) $view="hourly";

foreach($filename_array as $value) {
 	$view_pattern = '/' . $view . '/';
 	if (preg_match($view_pattern,$value)) {
		$subvalue=explode($view,$value);
		#print "$subvalue[1]";
		print "<a href=\"index.php?view=$subvalue[1]\">";
		print "<img src=\"./$value\" border=\"0\" alt=\"$value\" />";
		print "</a>";
		print "<p />";
	}
}
?>
</center>
Graphs created with <a href="http://www.bl.org/~jpk/graphdefang">GraphDefang</a>.
<br/><br/>
Interactive CGI Version at: <a href="./graphdefang.cgi">GraphDefang CGI</a>.
<p align="left">
  <a href="http://validator.w3.org/check/referer"><img
  src="http://www.w3.org/Icons/valid-xhtml10"
  alt="Valid XHTML 1.0!" height="31" width="88" border="0"/></a>
</p>
</body>
</html>
