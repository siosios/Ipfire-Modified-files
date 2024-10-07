#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2011  IPFire Team  <info@ipfire.org>                          #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";

my %color = ();
my %mainsettings = ();
my %speedparams=();

$speedparams{'ACTION'} = '';

&General::readhash("${General::swroot}/main/settings", \%mainsettings);
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'status information'}, 1, '');
&Header::openbigbox('100%', 'left');
&Header::getcgihash(\%speedparams);

&Header::openbox('100%', 'left',"Speedtest");

print <<END 
<table width="100%">
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<tr>
	<td align="center"><input type='submit' name='ACTION' value="$Lang::tr{'start'}"></td>
</tr>
</table>
END
;
my @speed = `net-test | grep -oP '(?<=Average network usage: )[0-9]+'`;
print '<br><PRE>';

if ( $speedparams{'ACTION'} eq "$Lang::tr{'start'}" )
{
my @qualitycheck = `net-test`;
print 'OUTPUT:';
if (@speed <= 10)
	{
	print "@qualitycheck";
	}
	else {
		print "@qualitycheck";
# Run speedtest-cli.
if ( -e "/usr/bin/speedtest1" ) {
	my @speedtest = `speedtest1 --accept-license`;
	print "@speedtest";
}
else {
	my @speedtest = "Error:  The speedtest-cli addon is not installed.  Use pakfire to install the speedtest-cli addon before running speedtest.";
	
}
}
}
print '</Pre>';

print"<br><table width='100%'><tr><td align='center'><a href='/cgi-bin/speedtest.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td></tr></table>";
&Header::closebox();

&Header::closebigbox();
&Header::closepage();
