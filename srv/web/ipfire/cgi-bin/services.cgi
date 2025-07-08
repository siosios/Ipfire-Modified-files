#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2005-2021  IPFire Team                                        #
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
use feature "switch";
no warnings 'experimental';
# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "${General::swroot}/graphs.pl";
require "/opt/pakfire/lib/functions.pl";

my %color = ();
my %mainsettings = ();
my %netsettings=();
&General::readhash("${General::swroot}/main/settings", \%mainsettings);
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);
&General::readhash("${General::swroot}/ethernet/settings", \%netsettings);

#workaround to suppress a warning when a variable is used only once
my @dummy = ( ${Header::colourred} );
undef (@dummy);

my %cgiparams=();

my @querry = split(/\?/,$ENV{'QUERY_STRING'});
$querry[0] = '' unless defined $querry[0];
$querry[1] = 'hour' unless defined $querry[1];

	&Header::showhttpheaders();
	&Header::openpage($Lang::tr{'status information'}, 1, '');
	&Header::openbigbox('100%', 'left');

	&Header::opensection();

	&Header::ServiceStatus({
		# DHCP Server
		$Lang::tr{'dhcp server'} => {
			"process" => "dhcpd",
		},

		# Web Server
		$Lang::tr{'web server'} => {
			"process" => "httpd",
		},

		# Cron Server
		$Lang::tr{'cron server'} => {
			"process" => "fcron",
		},

		# DNS Proxy
		$Lang::tr{'dns proxy server'} => {
			"process" => "unbound",
		},

		# Syslog
		$Lang::tr{'logging server'} => {
			"process" => "syslogd",
		},

		# Kernel Logger
		$Lang::tr{'kernel logging server'} => {
			"process" => "klogd",
		},

		# Time Server
		$Lang::tr{'ntp server'} => {
			"process" => "ntpd",
		},

		# SSH Server
		$Lang::tr{'secure shell server'} => {
			"process" => "sshd",
		},

		# IPsec
		$Lang::tr{'vpn'} => {
			"process" => "charon",
		},

		# Web Proxy
		$Lang::tr{'web proxy'} => {
			"process" => "squid",
		},

		# IPS
		$Lang::tr{'intrusion prevention system'} => {
			"pidfile" => "/var/run/suricata.pid",
		},
		
		#netdata
		$Lang::tr{'netdata server'} => {
			"process" => "netdata",
		},

		# OpenVPN Roadwarrior
		$Lang::tr{'ovpn roadwarrior server'} => {
			"process" => "openvpn",
			"pidfile" => "/var/run/openvpn.pid",
		}
	});

	&Header::closesection();

	&Header::openbox('100%', 'left', "$Lang::tr{addon} - $Lang::tr{services}");
	my $paramstr=$ENV{QUERY_STRING};
	my @param=split(/!/, $paramstr);
	# Make sure action parameter is actually one of the allowed service actions
	given ($param[1]) {
		when ( ['start', 'stop', 'restart', 'enable', 'disable'] ) {
			# Make sure pak-name and service name don't contain any illegal character
			if ( $param[0] !~ /[^a-zA-Z_0-9\-]/ &&
			     $param[2] !~ /[^a-zA-Z_0-9\-]/ ) {
				&General::system("/usr/local/bin/addonctrl", "$param[0]", "$param[1]", "$param[2]");
			}
		}
	}

	print <<END
<table class='tbl'>
<tr>
	<th align='left'><b>$Lang::tr{addon} $Lang::tr{service}</b></th>
	<th align='center'><b>Boot</b></th>
	<th align='center' colspan=2><b>$Lang::tr{'action'}</b></th>
	<th align='center'><b>$Lang::tr{'status'}</b></th>
	<th align='center'><b>$Lang::tr{'memory'}</b></th>
</tr>
END
;

	my @paks;
	my @addon_services;

	# Generate list of installed addon pak services
	my %paklist = &Pakfire::dblist("installed");

	foreach my $pak (sort keys %paklist) {
		my %metadata = &Pakfire::getmetadata($pak, "installed");

		my $service;

		if ("$metadata{'Services'}") {
			foreach $service (split(/ /, "$metadata{'Services'}")) {
				# Add addon name to displayname of service if servicename differs from addon
				my $displayname = ($pak ne $service) ? "$service ($pak)" : $service;

		if ($displayname =~ 'netdata') {
				print "<td align='left' width='31%'><a href=\'https:\/\/$ENV{'SERVER_ADDR'}:19222\' target=\"_blank\">$Lang::tr{'netdata server'}</a></td>";
		}else{
				print "<td align='left' width='31%'>$displayname</td> ";
				}

				my $status = isautorun($pak,$service);
				print "$status ";
				my $status = isrunningaddon($pak,$service);
				$status =~ s/\\[[0-1]\;[0-9]+m//g;

				chomp($status);
				print "$status";
				print "</tr>";
			}
		}
	}

	print "</table>\n";

	&Header::closebox();

	&Header::closebigbox();
	&Header::closepage();

sub isautorun (@) {
	my ($pak, $service) = @_;
	my @testcmd = &General::system_output("/usr/local/bin/addonctrl", "$pak", "boot-status", "$service");
	my $testcmd = @testcmd[0];
	my $status = "<td align='center'><img alt='$Lang::tr{'service boot setting unavailable'}' title='$Lang::tr{'service boot setting unavailable'}' src='/images/dialog-warning.png' border='0' width='16' height='16' /></td>";

	# Check if autorun for the given service is enabled.
	if ( $testcmd =~ /enabled\ on\ boot/ ) {
		# Adjust status.
		$status = "<td align='center'><a href='services.cgi?$pak!disable!$service'><img alt='$Lang::tr{'deactivate'}' title='$Lang::tr{'deactivate'}' src='/images/on.gif' border='0' width='16' height='16' /></a></td>";
	} elsif ( $testcmd =~ /disabled\ on\ boot/ ) {
		# Adjust status.
		$status = "<td align='center'><a href='services.cgi?$pak!enable!$service'><img alt='$Lang::tr{'activate'}' title='$Lang::tr{'activate'}' src='/images/off.gif' border='0' width='16' height='16' /></a></td>";
	}

	# Return the status.
	return $status;
}

sub isrunningaddon (@) {
	my ($pak, $service) = @_;

	my $status = "<td class='status is-stopped is-fixed'>$Lang::tr{'stopped'}</td><td colspan='2'></td>";
	my $testcmd = '';
	my $exename;

	my @testcmd = &General::system_output("/usr/local/bin/addonctrl", "$pak", "status", "$service");
	my $testcmd = @testcmd[0];

	if ( $testcmd =~ /is\ running/ && $testcmd !~ /is\ not\ running/){
		$status = "<td align='center' width='8%'><a href='services.cgi?$pak!stop!$service'><img alt='$Lang::tr{'stop'}' title='$Lang::tr{'stop'}' src='/images/go-down.png' border='0' /></a></td> ";
		$status .= "<td align='center' width='8%'><a href='services.cgi?$pak!restart!$service'><img alt='$Lang::tr{'restart'}' title='$Lang::tr{'restart'}' src='/images/reload.gif' border='0' /></a></td> ";
		$status .= "<td class='status is-running'>$Lang::tr{'running'}</td>";
		$testcmd =~ s/.* //gi;
		$testcmd =~ s/[a-z_]//gi;
		$testcmd =~ s/\[[0-1]\;[0-9]+//gi;
		$testcmd =~ s/[\(\)\.]//gi;
		$testcmd =~ s/  //gi;
		$testcmd =~ s///gi;

		my @pid = split(/\s/,$testcmd);

		# Fetch the memory consumption
		my $memory = &General::get_memory_consumption(@pid);

		# Format memory
		$memory = &General::formatBytes($memory);

		$status .="<td align='right'>$memory</td>";
	}else{
		$status = "<td align='center' width='16%' colspan=2><a href='services.cgi?$pak!start!$service'><img alt='$Lang::tr{'start'}' title='$Lang::tr{'start'}' src='/images/go-up.png' border='0' /></a></td>";
		$status .= "<td class='status is-stopped is-fixed'>$Lang::tr{'stopped'}</td><td colspan='2'></td>";
	}
	return $status;
}
