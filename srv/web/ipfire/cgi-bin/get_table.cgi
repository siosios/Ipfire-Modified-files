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
# Provides JSON data for the connections table, filtered by zone, IP, port,   #
# and protocol, including NAT information.                                    #
#                                                                             #
###############################################################################

use strict;
use warnings;
use CGI qw(escape);
use JSON::PP;
use CGI::Carp qw(fatalsToBrowser);
require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "${General::swroot}/ids-functions.pl";
require "${General::swroot}/location-functions.pl";

# Debugging switch (0 = off, 1 = critical, 2 = summary, 3 = detailed)
my $DEBUG = 3;

# Log debug message if debugging is enabled at the specified level
sub debug($$) {
    my ($level, $message) = @_;
    print STDERR "[DEBUG:$level] $message\n" if $DEBUG >= $level;
}

debug(1, "Script started");

# Color for multicast networks
my $colour_multicast = "#A0A0A0";

# Cache for IP-to-color mappings (cleared each request)
my %ipcolour_cache = ();
debug(2, "Initialized ipcolour_cache");

# Load ethernet settings
my %settings = ();
&General::readhash("/var/ipfire/ethernet/settings", \%settings);
debug(2, "Ethernet settings loaded: " . scalar(keys %settings) . " entries");

# Initialize known networks with their zone colors
my %networks = (
    "127.0.0.0/8" => ${Header::colourfw},
    "224.0.0.0/3" => $colour_multicast,
);
debug(2, "Initial networks: " . scalar(keys %networks) . " entries");

# Add network settings for each zone
foreach my $zone (qw(GREEN BLUE ORANGE)) {
    my $address_key = "${zone}_ADDRESS";
    my $netaddress_key = "${zone}_NETADDRESS";
    my $netmask_key = "${zone}_NETMASK";
    if (exists $settings{$address_key} && defined $settings{$address_key} && $settings{$address_key} =~ m/^\d+\.\d+\.\d+\.\d+$/) {
        $networks{"$settings{$address_key}/32"} = ${Header::colourfw};
        debug(3, "Added $zone address: $settings{$address_key}/32 => ${Header::colourfw}");
    }
    if (exists $settings{$netaddress_key} && defined $settings{$netaddress_key} && $settings{$netaddress_key} =~ m/^\d+\.\d+\.\d+\.\d+$/ &&
        exists $settings{$netmask_key} && defined $settings{$netmask_key} && $settings{$netmask_key} =~ m/^\d+\.\d+\.\d+\.\d+$/) {
        my $color = $zone eq 'GREEN' ? ${Header::colourgreen} :
                    $zone eq 'BLUE' ? ${Header::colourblue} :
                    ${Header::colourorange};
        $networks{"$settings{$netaddress_key}/$settings{$netmask_key}"} = $color;
        debug(3, "Added $zone network: $settings{$netaddress_key}/$settings{$netmask_key} => $color");
    }
}

# Add RED interface address
my $address = &IDS::get_red_address();
if ($address) {
    $networks{"${address}/32"} = ${Header::colourfw};
    debug(3, "Added RED interface address: ${address}/32 => ${Header::colourfw}");
}

# Add aliases with validation
my @aliases = &IDS::get_aliases();
my $alias_errors = 0;
foreach my $alias (@aliases) {
    if ($alias =~ m/^\d+\.\d+\.\d+\.\d+$/) {
        $networks{"${alias}/32"} = ${Header::colourfw};
        debug(3, "Added alias: ${alias}/32 => ${Header::colourfw}");
    } else {
        debug(1, "Invalid alias IP: $alias");
        debug(3, "Skipping alias: $alias (invalid format)");
        $alias_errors++;
    }
}
debug(2, "Aliases processed: " . scalar(@aliases) . " entries, $alias_errors errors");

# Initialize interfaces
my %interfaces = ();
foreach my $zone (qw(GREEN BLUE ORANGE)) {
    my $dev_key = "${zone}_DEV";
    if (exists $settings{$dev_key} && defined $settings{$dev_key} && $settings{$dev_key} =~ m/^[a-zA-Z0-9_-]+$/) {
        my $color = $zone eq 'GREEN' ? ${Header::colourgreen} :
                    $zone eq 'BLUE' ? ${Header::colourblue} :
                    ${Header::colourorange};
        $interfaces{$settings{$dev_key}} = $color;
        debug(3, "Interface $settings{$dev_key} => color $color");
    }
}
$interfaces{"gre[0-9]+"} = ${Header::colourvpn};
$interfaces{"vti[0-9]+"} = ${Header::colourvpn};
$interfaces{"tun[0-9]+"} = ${Header::colourovpn};
debug(2, "Added VPN interfaces: gre[0-9]+, vti[0-9]+, tun[0-9]+");

# Add routes to networks with validation
my @routes = &General::system_output("ip", "route", "show");
my $route_errors = 0;
debug(2, "Routes: " . scalar(@routes) . " entries");
foreach my $intf (keys %interfaces) {
    next if ($intf eq "");
    foreach my $route (grep(/dev ${intf}/, @routes)) {
        if ($route =~ m/^(\d+\.\d+\.\d+\.\d+\/\d+)/) {
            $networks{$1} = $interfaces{$intf};
            debug(3, "Route $1 assigned color $interfaces{$intf}");
        } else {
            debug(1, "Invalid route format for interface $intf: $route");
            debug(3, "Skipping route: $route (invalid format)");
            $route_errors++;
        }
    }
}
debug(2, "Routes processed: $route_errors errors");

# Add WireGuard settings
if (-e "/var/ipfire/wireguard/settings") {
    my %wgsettings = ();
    &General::readhash("/var/ipfire/wireguard/settings", \%wgsettings);
    if (exists $wgsettings{'CLIENT_POOL'} && defined $wgsettings{'CLIENT_POOL'} && $wgsettings{'CLIENT_POOL'} ne '') {
        $networks{$wgsettings{'CLIENT_POOL'}} = ${Header::colourwg};
        debug(3, "WireGuard client pool $wgsettings{'CLIENT_POOL'} assigned color ${Header::colourwg}");
    }
}

# Add WireGuard peers
if (-e "/var/ipfire/wireguard/peers") {
    my %wgpeers = ();
    &General::readhasharray("/var/ipfire/wireguard/peers", \%wgpeers);
    foreach my $key (keys %wgpeers) {
        my $networks_str = $wgpeers{$key}[8];
        my @networks_list = split(/\|/, $networks_str);
        foreach my $network (@networks_list) {
            if ($network && &Network::check_subnet($network)) {
                $networks{$network} = ${Header::colourwg};
                debug(3, "WireGuard peer $key subnet $network assigned color ${Header::colourwg}");
            }
        }
    }
}

# Add OpenVPN settings
if (-e "${General::swroot}/ovpn/settings") {
    my %ovpnsettings = ();
    &General::readhash("${General::swroot}/ovpn/settings", \%ovpnsettings);
    if (exists $ovpnsettings{'DOVPN_SUBNET'} && defined $ovpnsettings{'DOVPN_SUBNET'} && $ovpnsettings{'DOVPN_SUBNET'} ne '') {
        $networks{$ovpnsettings{'DOVPN_SUBNET'}} = ${Header::colourovpn};
        debug(3, "OpenVPN subnet $ovpnsettings{'DOVPN_SUBNET'} assigned color ${Header::colourovpn}");
    }
}

# Add OpenVPN client subnets
if (-e "${General::swroot}/ovpn/ccd.conf") {
    open(my $OVPNSUB, "${General::swroot}/ovpn/ccd.conf") or do {
        debug(1, "Could not open ${General::swroot}/ovpn/ccd.conf: $!");
        next;
    };
    while (my $line = <$OVPNSUB>) {
        chomp $line;
        my @ovpn = split(',', $line);
        if (@ovpn >= 3 && defined $ovpn[2] && $ovpn[2] ne '' && &Network::check_subnet($ovpn[2])) {
            $networks{$ovpn[2]} = ${Header::colourovpn};
            debug(3, "OpenVPN ccd subnet $ovpn[2] assigned color ${Header::colourovpn}");
        }
    }
    close($OVPNSUB);
}

# Add IPsec subnets
open(my $IPSEC, "${General::swroot}/vpn/config") or do {
    debug(1, "Could not open ${General::swroot}/vpn/config: $!");
    next;
};
my @ipsec = <$IPSEC>;
close($IPSEC);
foreach my $line (@ipsec) {
    chomp $line;
    my @vpn = split(',', $line);
    my @subnets = split(/\|/, $vpn[12]);
    for my $subnet (@subnets) {
        if ($subnet && &Network::check_subnet($subnet)) {
            $networks{$subnet} = ${Header::colourvpn};
            debug(3, "IPsec subnet $subnet assigned color ${Header::colourvpn}");
        }
    }
}

# Add OpenVPN net-to-net subnets
if (-e "${General::swroot}/ovpn/n2nconf") {
    open(my $OVPNN2N, "${General::swroot}/ovpn/ovpnconfig") or do {
        debug(1, "Could not open ${General::swroot}/ovpn/ovpnconfig: $!");
        next;
    };
    while (my $line = <$OVPNN2N>) {
        chomp $line;
        my @ovpn = split(',', $line);
        next if ($ovpn[4] ne 'net' || !defined $ovpn[12] || $ovpn[12] eq '');
        if (&Network::check_subnet($ovpn[12])) {
            $networks{$ovpn[12]} = ${Header::colourovpn};
            debug(3, "OpenVPN net-to-net subnet $ovpn[12] assigned color ${Header::colourovpn}");
        }
    }
    close($OVPNN2N);
}

# Sort networks by prefix length
my @networks = reverse sort {
    &Network::get_prefix($a) <=> &Network::get_prefix($b)
} grep { defined($_) && &Network::check_subnet($_) } keys %networks;
debug(2, "Final sorted networks: " . scalar(@networks) . " entries");

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
debug(2, "Zones defined: " . scalar(keys %zones) . " entries");

# Process CGI parameters and output JSON header
my $cgi = CGI->new;
debug(1, "CGI object created");
print $cgi->header('application/json');
debug(1, "JSON header sent");

my @valid_zones = qw(LAN INTERNET DMZ Wireless IPFire VPN WireGuard OpenVPN Multicast);
my @zone_params = grep { defined $_ && $_ ne '' } $cgi->multi_param('zone');
debug(2, "CGI parameter zones: " . join(", ", @zone_params));
my @selected_zones = grep { my $z = $_; defined $z && $z ne '' && grep { $_ eq $z } @valid_zones } @zone_params;
debug(2, "Selected zones: " . join(", ", @selected_zones));
my %selected_zones_hash = map { $_ => 1 } @selected_zones;
my $search_ip = $cgi->param('ip') || '';
my $search_port = $cgi->param('port') || '';
my $search_protocol = $cgi->param('protocol') || '';
my $search_enabled = $cgi->param('search_enabled') || '';
my $matches_zone;
my $matches_search;
debug(2, "Search parameters: ip=$search_ip, port=$search_port, protocol=$search_protocol, enabled=$search_enabled");

# Sanitize search parameters
if ($search_ip) {
    $search_ip =~ s/[^0-9.]//g;
    debug(3, "Sanitized search_ip: $search_ip");
}
if ($search_port) {
    $search_port =~ s/\D//g;
    if ($search_port < 0 || $search_port > 65535) {
        $search_port = '';
        debug(1, "Invalid search_port: $search_port, cleared");
    }
    debug(3, "Sanitized search_port: $search_port");
}
if ($search_protocol) {
    $search_protocol =~ s/[^a-zA-Z0-9]//g;
    debug(3, "Sanitized search_protocol: $search_protocol");
}

# Load and sort connection tracking data
debug(1, "Starting conntrack loading");
my @conntrack_data = &General::system_output("/usr/local/bin/getconntracktable");
debug(1, "Read " . scalar(@conntrack_data) . " lines from getconntracktable");
my @sorted_conntrack = sort { (split(' ', $b))[4] <=> (split(' ', $a))[4] } @conntrack_data;
debug(1, "Sorted conntrack data: " . scalar(@sorted_conntrack) . " lines");

# Process connection data
my @table_data = ();
my $conn_count = 0;
my $error_count = 0;
my $zone_matches = 0;
my $search_matches = 0;
my $ipcolour_cache_hits = 0;
debug(1, "Starting conntrack processing");
foreach my $line (@sorted_conntrack) {
    $conn_count++;
    my @conn = split(' ', $line);
    unless ($conn[0] eq 'ipv4') {
        debug(1, "Invalid connection $conn_count: non-IPv4");
        debug(3, "Skipping line: $line") if $conn_count <= 5;
        $error_count++;
        next;
    }

    my $l3proto = $conn[0];
    my $l4proto = $conn[2];
    if ($l4proto eq 'unknown') {
        my $l4protonum = $conn[3];
        if ($l4protonum eq '2') {
            $l4proto = 'IGMP';
        } elsif ($l4protonum eq '4') {
            $l4proto = 'IPv4 Encap';
        } elsif ($l4protonum eq '33') {
            $l4proto = 'DCCP';
        } elsif ($l4protonum eq '41') {
            $l4proto = 'IPv6 Encap';
        } elsif ($l4protonum eq '50') {
            $l4proto = 'ESP';
        } elsif ($l4protonum eq '51') {
            $l4proto = 'AH';
        } elsif ($l4protonum eq '132') {
            $l4proto = 'SCTP';
        } else {
            $l4proto = $l4protonum;
            debug(1, "Invalid connection $conn_count: unknown protocol $l4protonum");
            debug(3, "Line: $line") if $conn_count <= 5;
            $error_count++;
            next;
        }
    } else {
        $l4proto = uc($l4proto);
    }

    my $sip = '';
    my $sip_ret = '';
    my $dip = '';
    my $dip_ret = '';
    my $sport = '';
    my $sport_ret = '';
    my $dport = '';
    my $dport_ret = '';
    my @packets = ();
    my @bytes = ();
    my $ttl = $conn[4];
    my $state = $l4proto eq 'TCP' ? $conn[5] : '';
	
    # Parse connection details
    my $parse_error = 0;
    foreach my $item (@conn) {
        unless ($item =~ m/=/) {
            next;
        }
        my ($key, $val) = split('=', $item);
        unless (defined $val) {
            debug(1, "Invalid connection $conn_count: missing value for $key");
            debug(3, "Line: $line") if $conn_count <= 5;
            $parse_error = 1;
            last;
        }
        if ($key eq "src") {
            if ($sip eq '') {
                $sip = $val;
            } else {
                $dip_ret = $val;
            }
        } elsif ($key eq "dst") {
            if ($dip eq '') {
                $dip = $val;
            } else {
                $sip_ret = $val;
            }
        } elsif ($key eq "sport") {
            if ($sport eq '') {
                $sport = $val;
            } else {
                $dport_ret = $val;
            }
        } elsif ($key eq "dport") {
            if ($dport eq '') {
                $dport = $val;
            } else {
                $sport_ret = $val;
            }
        } elsif ($key eq "packets") {
            push(@packets, $val);
        } elsif ($key eq "bytes") {
            push(@bytes, $val);
        }
    }
    if ($parse_error || !$sip || !$dip) {
        debug(1, "Invalid connection $conn_count: incomplete data (sip=$sip, dip=$dip)");
        debug(3, "Line: $line") if $conn_count <= 5;
        $error_count++;
        next;
    }
    debug(3, "Connection: proto=$l4proto src=$sip:$sport dst=$dip:$dport") if $conn_count <= 5;

    my $sip_colour = ipcolour($sip);
    debug(3, "ipcolour for $sip returned $sip_colour") if $conn_count <= 5;
    my $dip_colour = $dip_ret && $dip ne $dip_ret ? ipcolour($dip_ret) : ipcolour($dip);
    debug(3, "ipcolour for $dip/$dip_ret returned $dip_colour") if $conn_count <= 5;

# Filter by selected zones
my $matches_zone;
if (@selected_zones) {
    $matches_zone = 0;
    for my $zone (@selected_zones) {
        if (exists $zones{$zone}) {
            if ($sip_colour eq $zones{$zone} || $dip_colour eq $zones{$zone}) {
                $matches_zone = 1;
                $zone_matches++;
                last;
            }
        }
    }
} else {
    # No zone filter set, so this connection counts as a zone match by default
    $matches_zone = 1;
    $zone_matches++;
}

debug(3, "Zone match for connection $conn_count: " . ($matches_zone ? "YES" : "NO")) if $conn_count <= 5;
debug(3, "Connection passed zone filter: proto=$l4proto src=$sip:$sport dst=$dip:$dport") if $matches_zone && $conn_count <= 5;
next unless $matches_zone;
    # Apply search filters
    if ($search_enabled && ($search_ip || $search_port || $search_protocol)) {
        my $matches_search = 1;
        if ($search_ip && $matches_search) {
            $matches_search = 0;
            if (($sip && $sip =~ /\Q$search_ip\E/i) ||
                ($sip_ret && $sip_ret =~ /\Q$search_ip\E/i) ||
                ($dip && $dip =~ /\Q$search_ip\E/i) ||
                ($dip_ret && $dip_ret =~ /\Q$search_ip\E/i)) {
                $matches_search = 1;
            }
        }
        if ($search_port && $matches_search) {
            $matches_search = 0;
            if (($sport && $sport eq $search_port) ||
                ($sport_ret && $sport_ret eq $search_port) ||
                ($dport && $dport eq $search_port) ||
                ($dport_ret && $dport_ret eq $search_port)) {
                $matches_search = 1;
            }
        }
        if ($search_protocol && $matches_search) {
            $matches_search = 0;
            if (lc($l4proto) eq lc($search_protocol)) {
                $matches_search = 1;
            }
        }

        debug(3, "Search match for connection $conn_count: " . ($matches_search ? "YES" : "NO")) if $conn_count <= 5;
        next unless $matches_search;
        $search_matches++;
    }


#debug(3, "Resolving service for src port $sport") if defined($sport);
#debug(3, "Resolving service for dst port $dport") if defined($dport);

# Helper function to validate if the port is numeric and not empty
sub is_valid_port {
    my ($port) = @_;
    return defined($port) && $port ne '' && $port =~ /^\d+$/ && $port >= 0 && $port <= 65535;
}

# Resolve service names for well-known ports
my $sserv = is_valid_port($sport) ? uc(getservbyport($sport, lc($l4proto)) || '') : '';
my $dserv = is_valid_port($dport) ? uc(getservbyport($dport, lc($l4proto)) || '') : '';
my $sserv_ret = is_valid_port($sport_ret) ? uc(getservbyport($sport_ret, lc($l4proto)) || '') : '';
my $dserv_ret = is_valid_port($dport_ret) ? uc(getservbyport($dport_ret, lc($l4proto)) || '') : '';


    # Resolve country codes and flag icons - ADDING CHECKS HERE
    my $srcccode = defined($sip) ? &Location::Functions::lookup_country_code($sip_ret || $sip) : '';
    my $src_flag_icon = defined($srcccode) ? &Location::Functions::get_flag_icon($srcccode) : '/images/flags/unknown.png';
    if ($src_flag_icon && $src_flag_icon !~ m!^/images/flags/!) {
        $src_flag_icon = "/images/flags/" . lc($srcccode) . ".png" if $srcccode;
    }
    my $dstccode = defined($dip) ? &Location::Functions::lookup_country_code($dip_ret || $dip) : '';
    my $dst_flag_icon = defined($dstccode) ? &Location::Functions::get_flag_icon($dstccode) : '/images/flags/unknown.png';
    if ($dst_flag_icon && $dst_flag_icon !~ m!^/images/flags/!) {
        $dst_flag_icon = "/images/flags/" . lc($dstccode) . ".png" if $dstccode;
    }

    # Add connection data to table - ADDING CHECKS HERE
	debug(3, "Connection $conn_count to be added. Proto: $l4proto, Src: $sip:$sport, Dst: $dip:$dport");
    push @table_data, {
        protocol => defined($l4proto) ? $l4proto : '',
        src_ip => defined($sip) ? $sip : '',
        src_ret => defined($sip_ret) ? $sip_ret : '',
        dst_ip => defined($dip) ? $dip : '',
        dst_ret => defined($dip_ret) ? $dip_ret : '',
        src_port => defined($sport) ? $sport : '',
        src_ret_port => defined($sport_ret) ? $sport_ret : '',
        dst_port => defined($dport) ? $dport : '',
        dst_ret_port => defined($dport_ret) ? $dport_ret : '',
        src_service => $sserv,
        src_ret_service => $sserv_ret,
        dst_service => $dserv,
        dst_ret_service => $dserv_ret,
        src_colour => defined($sip_colour) ? $sip_colour : '#FFFFFF',
        dst_colour => defined($dip_colour) ? $dip_colour : '#FFFFFF',
        src_country => $srcccode,
        src_flag_icon => $src_flag_icon,
        dst_country => $dstccode,
        dst_flag_icon => $dst_flag_icon,
        bytes_in => defined($bytes[0]) ? &General::formatBytes($bytes[0]) : '',
        bytes_out => defined($bytes[1]) ? &General::formatBytes($bytes[1]) : '',
        state => $state,
        ttl => defined($ttl) ? &General::format_time($ttl) : '',
    };
    debug(3, "Added connection $conn_count to table_data") if $conn_count <= 5;
}

debug(1, "Processed $conn_count/" . scalar(@sorted_conntrack) . " connections, $error_count errors");
debug(1, "Connections after filtering: " . scalar(@table_data));
debug(2, "Zone matches: $zone_matches/" . scalar(@sorted_conntrack) . " connections");
debug(2, "Search matches: $search_matches/" . scalar(@sorted_conntrack) . " connections") if $search_enabled;
debug(2, "ipcolour cache hits: $ipcolour_cache_hits");
debug(1, "Final Connection Data: " . encode_json(\@table_data));
# Output JSON data
debug(1, "Encoding JSON data");
print encode_json(\@table_data);
debug(1, "JSON data sent");
 exit;
# Determines the color for an IP address based on its network zone
# Args: IP address
# Returns: Color code for the zone
sub ipcolour {
    my ($address) = @_;
    debug(3, "ipcolour called for $address") if $conn_count <= 5;
    unless ($address =~ m/^\d+\.\d+\.\d+\.\d+$/) {
        debug(1, "Invalid IP address: $address");
        $ipcolour_cache{$address} = ${Header::colourred};
        return ${Header::colourred};
    }
    if (exists $ipcolour_cache{$address}) {
        $ipcolour_cache_hits++;
        debug(3, "ipcolour cache hit for $address: $ipcolour_cache{$address}") if $conn_count <= 5;
        return $ipcolour_cache{$address};
    }
    foreach my $network (keys %networks) {
        if (&Network::ip_address_in_network($address, $network)) {
            $ipcolour_cache{$address} = $networks{$network};
            debug(3, "ipcolour $address matched network $network with color $networks{$network}") if $conn_count <= 5;
            return $networks{$network};
        }
    }
    $ipcolour_cache{$address} = ${Header::colourred};
    debug(3, "ipcolour $address default to color ${Header::colourred}") if $conn_count <= 5;
    return ${Header::colourred};
}

1;
