#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2007-2025  IPFire Team  <info@ipfire.org>                     #
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
use CGI qw(escape);
use HTML::Entities;

# Enable for debugging
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "${General::swroot}/ids-functions.pl";
require "${General::swroot}/location-functions.pl";
require "${General::swroot}/network-functions.pl";

# Color for multicast networks
my $colour_multicast = "#A0A0A0";

# Cache for IP-to-color mappings
my %ipcolour_cache = ();

# Load ethernet settings
my %settings = ();
&General::readhash("/var/ipfire/ethernet/settings", \%settings);

# Initialize known networks with their zone colors
my %networks = (
	"127.0.0.0/8" => ${Header::colourfw},
	"224.0.0.0/3" => $colour_multicast,
);

# Add network settings for each zone
foreach my $zone (qw(GREEN BLUE ORANGE)) {
	if (exists $settings{"${zone}_ADDRESS"} && defined $settings{"${zone}_ADDRESS"} && $settings{"${zone}_ADDRESS"} ne '' && $settings{"${zone}_ADDRESS"} =~ m/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/) {
		$networks{"$settings{\"${zone}_ADDRESS\"}/32"} = ${Header::colourfw};
	}
	next unless exists $settings{"${zone}_NETADDRESS"} && exists $settings{"${zone}_NETMASK"} && defined $settings{"${zone}_NETADDRESS"} && defined $settings{"${zone}_NETMASK"};
	my $netaddress = $settings{"${zone}_NETADDRESS"};
	my $netmask = $settings{"${zone}_NETMASK"};
	if (defined $netaddress && $netaddress ne '' && $netaddress =~ m/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/ &&
	    defined $netmask && $netmask ne '' && $netmask =~ m/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/ &&
	    $netaddress ne '0.0.0.0' && $netmask ne '0.0.0.0') {
		$networks{"$netaddress/$netmask"} =
			$zone eq 'GREEN' ? ${Header::colourgreen} :
			$zone eq 'BLUE' ? ${Header::colourblue} :
			${Header::colourorange};
	}
}

# Add RED interface address
my $address = &IDS::get_red_address();
if ($address) {
	$networks{"${address}/32"} = ${Header::colourfw};
}

# Add aliases
my @aliases = &IDS::get_aliases();
for my $alias (@aliases) {
	$networks{"${alias}/32"} = ${Header::colourfw};
}

# Initialize interfaces
my %interfaces = ();
foreach my $zone (qw(GREEN BLUE ORANGE)) {
	if (exists $settings{"${zone}_DEV"} && defined $settings{"${zone}_DEV"} && $settings{"${zone}_DEV"} ne '' && $settings{"${zone}_DEV"} =~ m/^[a-zA-Z0-9_-]+$/) {
		$interfaces{$settings{"${zone}_DEV"}} =
			$zone eq 'GREEN' ? ${Header::colourgreen} :
			$zone eq 'BLUE' ? ${Header::colourblue} :
			${Header::colourorange};
	}
}
$interfaces{"gre[0-9]+"} = ${Header::colourvpn};
$interfaces{"vti[0-9]+"} = ${Header::colourvpn};
$interfaces{"tun[0-9]+"} = ${Header::colourovpn};

# Add routes to networks
my @routes = &General::system_output("ip", "route", "show");
foreach my $intf (keys %interfaces) {
	next if ($intf eq "");
	foreach my $route (grep(/dev ${intf}/, @routes)) {
		if ($route =~ m/^(\d+\.\d+\.\d+\.\d+\/\d+)/) {
			$networks{$1} = $interfaces{$intf};
		}
	}
}

# Add WireGuard settings
if (-e "/var/ipfire/wireguard/settings") {
	my %wgsettings = ();
	&General::readhash("/var/ipfire/wireguard/settings", \%wgsettings);
	if (exists $wgsettings{'CLIENT_POOL'} && defined $wgsettings{'CLIENT_POOL'} && $wgsettings{'CLIENT_POOL'} ne '') {
		$networks{$wgsettings{'CLIENT_POOL'}} = ${Header::colourwg};
	}
}

# Add WireGuard peers
if (-e "/var/ipfire/wireguard/peers") {
	my %wgpeers = ();
	&General::readhasharray("/var/ipfire/wireguard/peers", \%wgpeers);
	foreach my $key (keys %wgpeers) {
		my $networks = $wgpeers{$key}[8];
		my @networks = split(/\|/, $networks);
		foreach my $network (@networks) {
			$networks{$network} = ${Header::colourwg} if $network && &Network::check_subnet($network);
		}
	}
}

# Add OpenVPN settings
if (-e "${General::swroot}/ovpn/settings") {
	my %ovpnsettings = ();
	&General::readhash("${General::swroot}/ovpn/settings", \%ovpnsettings);
	if (exists $ovpnsettings{'DOVPN_SUBNET'} && defined $ovpnsettings{'DOVPN_SUBNET'} && $ovpnsettings{'DOVPN_SUBNET'} ne '') {
		$networks{$ovpnsettings{'DOVPN_SUBNET'}} = ${Header::colourovpn};
	}
}

# Add OpenVPN client subnets
if (-e "${General::swroot}/ovpn/ccd.conf") {
	open(OVPNSUB, "${General::swroot}/ovpn/ccd.conf") or next;
	while (my $line = <OVPNSUB>) {
		chomp $line;
		my @ovpn = split(',', $line);
		if (@ovpn >= 3 && defined $ovpn[2] && $ovpn[2] ne '' && &Network::check_subnet($ovpn[2])) {
			$networks{$ovpn[2]} = ${Header::colourovpn};
		}
	}
	close(OVPNSUB);
}

# Add IPsec subnets
open(IPSEC, "${General::swroot}/vpn/config") or next;
my @ipsec = <IPSEC>;
close(IPSEC);

foreach my $line (@ipsec) {
	chomp $line;
	my @vpn = split(',', $line);
	my @subnets = split(/\|/, $vpn[12]);
	for my $subnet (@subnets) {
		$networks{$subnet} = ${Header::colourvpn} if $subnet && &Network::check_subnet($subnet);
	}
}

# Add OpenVPN net-to-net subnets
if (-e "${General::swroot}/ovpn/n2nconf") {
	open(OVPNN2N, "${General::swroot}/ovpn/ovpnconfig") or next;
	while (my $line = <OVPNN2N>) {
		chomp $line;
		my @ovpn = split(',', $line);
		next if ($ovpn[4] ne 'net' || !defined $ovpn[12] || $ovpn[12] eq '');
		$networks{$ovpn[12]} = ${Header::colourovpn} if &Network::check_subnet($ovpn[12]);
	}
	close(OVPNN2N);
}

# Sort networks by prefix length
my @networks = reverse sort {
	&Network::get_prefix($a) <=> &Network::get_prefix($b)
} grep { defined($_) && &Network::check_subnet($_) } keys %networks;

# Define known zones with their colors
my %zones = (
	'LAN' => ${Header::colourgreen},
	'INTERNET' => ${Header::colourred},
	'DMZ' => ${Header::colourorange},
	'Wireless' => ${Header::colourblue},
	'IPFire' => ${Header::colourfw},
	'VPN' => ${Header::colourvpn},
	'WireGuard' => ${Header::colourwg},
	'OpenVPN' => ${Header::colourovpn},
	'Multicast' => $colour_multicast,
);

# Process CGI parameters
my $cgi = CGI->new;
my @valid_zones = qw(LAN INTERNET DMZ Wireless IPFire VPN WireGuard OpenVPN Multicast);
my @raw_zone_params = $cgi->multi_param('zone');
my @zone_params = grep { defined $_ && $_ ne '' } map { CGI::escapeHTML($_) } @raw_zone_params;
my @selected_zones = grep { my $z = $_; defined $z && $z ne '' && grep { $_ eq $z } @valid_zones } @zone_params;
my %selected_zones_hash = map { $_ => 1 } @selected_zones;
my $search_ip = $cgi->param('ip') || '';
my $search_port = $cgi->param('port') || '';
my $search_protocol = $cgi->param('protocol') || '';
my $search_enabled = $cgi->param('search_enabled') || '';
my $refresh_interval = $cgi->param('refresh_interval') || 0;

# Sanitize search parameters
if ($search_ip) {
	$search_ip =~ s/[^0-9.]//g;
}
if ($search_port) {
	$search_port =~ s/\D//g;
	if ($search_port < 0 || $search_port > 65535) {
		$search_port = '';
	}
}
if ($search_protocol) {
	$search_protocol =~ s/[^a-zA-Z0-9]//g;
}

# Output HTTP headers
&Header::showhttpheaders();

# Render page header and styles
&Header::openpage($Lang::tr{'connections'}, 1, <<'END'
<style>
	.search_fields { display: none; }
	#error_msg { color: red; margin-top: 10px; display: none; }
	th[data-sort] {
		cursor: pointer;
	}
	th.sort-asc::after {
		content: " ▶";
		font-size: smaller;
		color: #aaa;
	}
	th.sort-desc::after {
		content: " ◀";
		font-size: smaller;
		color: #aaa;
	}
</style>
<script src='/include/jquery.js'></script>
<script>
	$(document).ready(function() {
		if ($("#search_toggle").prop("checked")) {
			$(".search_fields").show();
		}
		$("#search_toggle").change(function() {
			$(".search_fields").toggle();
		});

		let refreshInterval = parseInt($("#refresh_interval").val() || 0) * 1000;
		let refreshTimer;

		let connectionsData = [];
		let sortColumn = 'protocol';
		let sortDirection = 'asc';

		function sortData(data, column, direction) {
			return data.sort(function(a, b) {
				let valA = a[column] || '';
				let valB = b[column] || '';

				if (column === 'bytes_in' || column === 'bytes_out') {
					valA = Number(valA);
					valB = Number(valB);
				} else if (column === 'ttl_seconds') {
					// Convert TTL to seconds for sorting
					valA = parseTTL(a.ttl);
					valB = parseTTL(b.ttl);
				} else {
					valA = valA.toString().toLowerCase();
					valB = valB.toString().toLowerCase();
				}

				if (valA < valB) return direction === 'asc' ? -1 : 1;
				if (valA > valB) return direction === 'asc' ? 1 : -1;
				return 0;
			});
		}

		function renderTable(data) {
			const tbody = $(".tbl tbody");
			tbody.empty();
			let connCount = 0;

			if (!data || !Array.isArray(data)) {
				$("#error_msg").text("Error: Invalid data format").show();
				$("#connection_count").text("(Error: Invalid data format)");
				return;
			}

			$("#error_msg").hide();
			$.each(data, function(i, item) {
				// NAT info extras
				const src_extra = (item.src_ret && item.src_ip !== item.src_ret) ?
					'<span style="color:#FFFFFF;"> ></span>  ' +
					'<a href="/cgi-bin/ipinfo.cgi?ip=' + encodeURIComponent(item.src_ret || '') + '">' +
					'<span style="color:#FFFFFF;">' + (item.src_ret || '') + '</span></a>' : '';
				const dst_extra = (item.dst_ret && item.dst_ip !== item.dst_ret) ?
					'<span style="color:#FFFFFF;"> ></span>  ' +
					'<a href="/cgi-bin/ipinfo.cgi?ip=' + encodeURIComponent(item.dst_ret || '') + '">' +
					'<span style="color:#FFFFFF;">' + (item.dst_ret || '') + '</span></a>' : '';
				const sport_extra = (item.src_ret_port && item.src_port !== item.src_ret_port) ?
					'<span style="color:#FFFFFF;"> ></span>  ' +
					'<a href="https://isc.sans.edu/port.html?port=' + encodeURIComponent(item.src_ret_port || '') + '" target="_blank" title="' + (item.src_ret_service || '') + '">' +
					'<span style="color:#FFFFFF;">' + (item.src_ret_port || '') + '</span></a>' : '';
				const dport_extra = (item.dst_ret_port && item.dst_port !== item.dst_ret_port) ?
					'<span style="color:#FFFFFF;">></span>  ' +
					'<a href="https://isc.sans.edu/port.html?port=' + encodeURIComponent(item.dst_ret_port || '') + '" target="_blank" title="' + (item.dst_ret_service || '') + '">' +
					'<span style="color:#FFFFFF;">' + (item.dst_ret_port || '') + '</span></a>' : '';

				const html = [
					'<tr>',
					'<td style="text-align:center">' + (item.protocol || '') + '</td>',
					'<td style="text-align:center; background-color:' + (item.src_colour || '#FFFFFF') + '">',
					'<a href="/cgi-bin/ipinfo.cgi?ip=' + encodeURIComponent(item.src_ip || '') + '"><span style="color:#FFFFFF;">' + (item.src_ip || '') + '</span></a>',
					src_extra,
					'</td>',
					'<td style="text-align:center; background-color:' + (item.src_colour || '#FFFFFF') + '">',
					'<a href="https://isc.sans.edu/port.html?port=' + encodeURIComponent(item.src_port || '') + '" target="_blank" title="' + (item.src_service || '') + '">',
					'<span style="color:#FFFFFF;">' + (item.src_port || '') + '</span>',
					'</a>',
					sport_extra,
					'</td>',
					'<td style="text-align:center; background-color:' + (item.src_colour || '#FFFFFF') + '">',
					'<a href="country.cgi#' + encodeURIComponent(item.src_country || '') + '">',
					'<img src="' + (item.src_flag_icon || '/images/flags/unknown.png') + '" border="0" align="absmiddle" alt="' + (item.src_country || '') + '" title="' + (item.src_country || '') + '" />',
					'</a>',
					'</td>',
					'<td style="text-align:center; background-color:' + (item.dst_colour || '#FFFFFF') + '">',
					'<a href="/cgi-bin/ipinfo.cgi?ip=' + encodeURIComponent(item.dst_ip || '') + '"><span style="color:#FFFFFF;">' + (item.dst_ip || '') + '</span></a>',
					dst_extra,
					'</td>',
					'<td style="text-align:center; background-color:' + (item.dst_colour || '#FFFFFF') + '">',
					'<a href="https://isc.sans.edu/port.html?port=' + encodeURIComponent(item.dst_port || '') + '" target="_blank" title="' + (item.dst_service || '') + '">',
					'<span style="color:#FFFFFF;">' + (item.dst_port || '') + '</span>',
					'</a>',
					dport_extra,
					'</td>',
					'<td style="text-align:center; background-color:' + (item.dst_colour || '#FFFFFF') + '">',
					'<a href="country.cgi#' + encodeURIComponent(item.dst_country || '') + '">',
					'<img src="' + (item.dst_flag_icon || '/images/flags/unknown.png') + '" border="0" align="absmiddle" alt="' + (item.dst_country || '') + '" title="' + (item.dst_country || '') + '" />',
					'</a>',
					'</td>',
					'<td class="text-right">' + (item.bytes_in || '') + '</td>',
					'<td class="text-right">' + (item.bytes_out || '') + '</td>',
					'<td style="text-align:center">' + (item.state || '') + '</td>',
					'<td style="text-align:center">' + (item.ttl || '') + '</td>',
					'</tr>'
				].join('');
				tbody.append(html);
				connCount++;
			});

			$("#connection_count").text('(' + connCount + ' Connections )');
			// Update sort indicators on headers
			$(".tbl thead th").removeClass("sort-asc sort-desc");
			$(".tbl thead th[data-sort='" + sortColumn + "']").addClass(sortDirection === 'asc' ? "sort-asc" : "sort-desc");
		}

		function updateTable() {
			const zones = $("input[name='zone']").map(function() { return $(this).val(); }).get();
			const params = {
				zone: zones,
				ip: $("input[name='ip']").val() || '',
				port: $("input[name='port']").val() || '',
				protocol: $("input[name='protocol']").val() || '',
				search_enabled: $("#search_toggle").is(":checked") ? 1 : 0
			};

			const queryString = $.param(params, true);

			$.ajax({
				url: '/cgi-bin/get_table.cgi?' + queryString,
				dataType: 'json',
				success: function(data) {
					if (!data || !Array.isArray(data)) {
						$("#error_msg").text("Error: Invalid data format").show();
						$("#connection_count").text("(Error: Invalid data format)");
						return;
					}
					$("#error_msg").hide();
					connectionsData = data;
					connectionsData = sortData(connectionsData, sortColumn, sortDirection);
					renderTable(connectionsData);
				},
				error: function(jqXHR, textStatus, errorThrown) {
					$("#error_msg").text("Error loading data: " + jqXHR.status + " " + textStatus).show();
					$("#connection_count").text("(Error loading data: " + jqXHR.status + " " + textStatus + ")");
				}
			});
		}

		// Click handler for sortable headers
		$(".tbl thead th[data-sort]").click(function() {
			const column = $(this).attr("data-sort");
			if (sortColumn === column) {
				sortDirection = (sortDirection === 'asc') ? 'desc' : 'asc';
			} else {
				sortColumn = column;
				sortDirection = 'asc';
			}
			connectionsData = sortData(connectionsData, sortColumn, sortDirection);
			renderTable(connectionsData);
		});

		$("#refresh_interval").change(function() {
			clearInterval(refreshTimer);
			refreshInterval = parseInt($(this).val() || 0) * 1000;
			if (refreshInterval > 0) {
				refreshTimer = setInterval(updateTable, refreshInterval);
			}
		});

		updateTable();
		if (refreshInterval > 0) {
			refreshTimer = setInterval(updateTable, refreshInterval);
		}
	});
</script>
END
);

# Render main page layout
&Header::openbigbox('100%', 'left');
&Header::opensection();

# Render zone legend
print <<END;
	<table style='width:100%'>
		<tr>
			<td style='text-align:center;'>
				<b>$Lang::tr{'legend'} :</b>
			</td>
END

foreach my $zone (@valid_zones) {
	my $style = $selected_zones_hash{$zone} ? "background-color: #e0e0e0;" : "";
	my $label = get_zone_label($zone) || $zone;
	my $href = build_zone_href($zone, \@selected_zones) || '#';
	print <<END;
			<td style='text-align:center; color:#FFFFFF; background-color:$zones{$zone}; font-weight:bold; $style'>
				<a href='$href' style='color:#FFFFFF; text-decoration:none;'>
					<b>$label</b>
				</a>
			</td>
END
}

print <<END;
		</tr>
	</table>
	<br>
	<div id="error_msg"></div>
END

# Generate filter text for active filters
my $filter_text = '';
if (@selected_zones || $search_enabled) {
	my @filter_parts;
	if (@selected_zones) {
		my @zone_labels = grep { defined $_ } map { get_zone_label($_) } @selected_zones;
		push @filter_parts, join(", ", @zone_labels) if @zone_labels;
	}
	if ($search_enabled) {
		push @filter_parts, ($Lang::tr{'ip address'} || 'IP address') . ": " . encode_entities($search_ip) if $search_ip && $search_ip ne '';
		push @filter_parts, "$Lang::tr{'port'}: " . encode_entities($search_port) if $search_port && $search_port ne '';
		push @filter_parts, "$Lang::tr{'protocol'}: " . encode_entities($search_protocol) if $search_protocol && $search_protocol ne '';
	}
	$filter_text = join(", ", @filter_parts) if @filter_parts;
}

# Render filter form
print <<END;
	<form method='get' action='$ENV{'SCRIPT_NAME'}'>
END

# Add hidden inputs for selected zones
foreach my $zone (@selected_zones) {
	print <<END;
		<input type='hidden' name='zone' value='@{[ CGI::escapeHTML($zone) ]}' />
END
}

print <<END;
		<label><input type='checkbox' id='search_toggle' name='search_enabled' @{[ $search_enabled ? 'checked' : '' ]}> $Lang::tr{'search'}</label>
		<div class='search_fields' style='margin-top:10px;'>
			<label>$Lang::tr{'ip address'}: <input type='text' name='ip' value='$search_ip' /></label>
			<label>$Lang::tr{'port'}: <input type='text' name='port' value='$search_port' /></label>
			<label>$Lang::tr{'protocol'} <input type='text' name='protocol' value='$search_protocol' /></label>
			<input type='submit' value='$Lang::tr{'search'}' />
		</div>
		@{[ $filter_text ? "<p><b>$Lang::tr{'connections filtered_by'} " . encode_entities($filter_text) . " <span id='connection_count'></span></b></p>" : '' ]}
		<label style='margin-top:10px; display:block;'>$Lang::tr{'connections refresh interval'}:
			<select id='refresh_interval' name='refresh_interval'>
				<option value='0' @{[ $refresh_interval == 0 ? 'selected' : '' ]}>$Lang::tr{'disabled'}</option>
				<option value='2' @{[ $refresh_interval == 2 ? 'selected' : '' ]}>2</option>
				<option value='5' @{[ $refresh_interval == 5 ? 'selected' : '' ]}>5</option>
				<option value='10' @{[ $refresh_interval == 10 ? 'selected' : '' ]}>10</option>
				<option value='30' @{[ $refresh_interval == 30 ? 'selected' : '' ]}>30</option>
				<option value='60' @{[ $refresh_interval == 60 ? 'selected' : '' ]}>60</option>
			</select>
		</label>
	</form>
	<br>
END

# Render connections table with sorting attributes on headers
print <<END;
	<table class="tbl">
		<thead>
			<tr>
				<th data-sort="protocol">$Lang::tr{'protocol'}</th>
				<th colspan='2' data-sort="src_ip">$Lang::tr{'source ip and port'}</th>
				<th></th>
				<th colspan='2' data-sort="dst_ip">$Lang::tr{'dest ip and port'}</th>
				<th></th>
				<th colspan='2'>$Lang::tr{'data transfer'}</th>
				<th data-sort="state">$Lang::tr{'connection'}<br>$Lang::tr{'status'}</th>
				<th>$Lang::tr{'expires'}<br>($Lang::tr{'hours:minutes:seconds'})</th>
			</tr>
		</thead>
		<tbody>
			<!-- Filled by JavaScript -->
		</tbody>
	</table>
END

# Close page layout
&Header::closesection();
&Header::closebigbox();
&Header::closepage();

# Determines the color for an IP address based on its network zone
sub ipcolour {
	my $address = shift;
	if (exists $ipcolour_cache{$address}) {
		return $ipcolour_cache{$address};
	}
	foreach my $network (@networks) {
		if (&Network::ip_address_in_network($address, $network)) {
			$ipcolour_cache{$address} = $networks{$network};
			return $networks{$network};
		}
	}
	$ipcolour_cache{$address} = ${Header::colourred};
	return ${Header::colourred};
}

# Builds a URL for toggling a zone filter
sub build_zone_href {
	my ($zone, $selected_zones_ref) = @_;
	return '#' unless defined $zone && $zone ne '';
	my @new_zones = @$selected_zones_ref;
	if ($selected_zones_hash{$zone}) {
		@new_zones = grep { $_ ne $zone } @new_zones;
	} else {
		push @new_zones, $zone;
	}
	# Only include zone parameters, reset search parameters
	my $href = "?" . join("&", map { "zone=" . CGI::escape($_) } @new_zones);
	return $href;
}

# Retrieves the display label for a zone
sub get_zone_label {
	my $zone = shift;
	return $zone unless defined $zone && $zone ne '';
	if ($zone eq 'IPFire') {
		return 'IPFire';
	} elsif ($zone eq 'Multicast') {
		return 'Multicast';
	} elsif ($zone eq 'OpenVPN') {
		return $Lang::tr{'OpenVPN'} || 'OpenVPN';
	} else {
		return $Lang::tr{lc($zone)} || $zone;
	}
}

1;