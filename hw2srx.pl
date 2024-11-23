#!/usr/bin/perl
use warnings;

#use strict;
use Data::Dumper;
use NetAddr::IP;
use Getopt::Std;
use Cwd 'abs_path';
use File::Basename;

# use feature "switch";

# use vars qw($opt_c);
# use v5.10.1;

#The major aim of the script is translate juniper's ssg config to juniper srx config

my $text;                       # save all config
my @texts;                      # save all config to array
my @set_source_address;
my @set_destination_address;
my $n                   = 0;    # line number for 1st cycle
my %huawei_srx_services = (
    any    => "any",
    ftp    => "junos-ftp",
    http   => "junos-http",
    https  => "junos-https",
    icmp   => "junos-ping",
    ntp    => "junos-ntp",
    rdp    => "junos-rdp",
    ssh    => "junos-ssh",
    syslog => "junos-syslog",
);

sub set_polices_address {
    local $address = $_[0];
    local $netmask = $_[1];
    local $hostname;
    local $ip;

    if ( $address ne $netmask ) {
        $ip = NetAddr::IP->new( $address, $netmask );
        my $masklength = $ip->masklen();
        if ( $masklength == 32 ) {
            $hostname = "host_$ip";
        }
        else {
            $hostname = "net_$ip/$masklength";
        }
    }
    else {
        $ip       = NetAddr::IP->new($address);
        $hostname = "host_$ip";
    }
    return $hostname, $ip;
}

sub set_polices {
    local $policy_name = $_[0];
    local ( @huawei_config, @srx_config );
    local (
        $action,      $src_zone,    $dst_zone,
        @src_address, @dst_address, @application
    );
    push @huawei_config, $texts[$n];
    $n++;
    until ( $texts[$n] eq "exit" ) {
        push @huawei_config, $texts[$n];
        local @cells = split /\s+/, $texts[$n];
        if ( $cells[0] eq "action" ) {
            $action = $cells[-1];
        }
        elsif ( $cells[0] eq "source-zone" ) {
            $src_zone = $cells[-1];
        }
        elsif ( $cells[0] eq "destination-zone" ) {
            $dst_zone = $cells[-1];
        }
        elsif ( $cells[0] eq "source-address" ) {
            if ( $cells[1] eq "address-set" ) {
                push @src_address, $cells[-1];
            }
            else {
                my ( $source_address, $real_ip ) =
                  set_polices_address( $cells[1], $cells[-1] );
                push @set_source_address,
"set security zones security-zone $src_zone address-book address $source_address $real_ip";
                push @src_address, $source_address;
            }
        }
        elsif ( $cells[0] eq "destination-address" ) {
            if ( $cells[1] eq "address-set" ) {
                push @dst_address, $cells[-1];
            }
            else {
                my ( $destination_address, $real_ip ) =
                  set_polices_address( $cells[1], $cells[-1] );
                push @set_destination_address,
"set security zones security-zone $dst_zone address-book address $destination_address $real_ip";
                push @dst_address, $destination_address;
            }
        }
        elsif ( $cells[0] eq "service" ) {
            push @application, $cells[-1];
        }
        $n++;
    }
    push @huawei_config, $texts[$n];

# if source address, destination address, application and action not defined, the policy will not function in hilston, so ignore these rules
# perl no longer support test array and hash by defined function, instead of if (@array or %hash)
    if (   defined( $src_zone && $dst_zone && $action )
        && ( @src_address && @dst_address && @application )
        && ( $src_zone ne "any" && $dst_zone ne "any" ) )
    {
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $policy_name match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print
"set security policies from-zone $src_zone to-zone $dst_zone policy $policy_name then $action\n";
        push @srx_config,
"set security policies from-zone $src_zone to-zone $dst_zone policy $policy_name match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        push @srx_config,
"set security policies from-zone $src_zone to-zone $dst_zone policy $policy_name then $action\n";
    }
    elsif ( defined( $src_zone && $dst_zone && $action )
        && ( @src_address && $dst_address && @application )
        && ( $src_zone eq "any" || $dst_zone eq "any" ) )
    {
        print
"set security policies global policy $policy_name match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print
"set security policies global policy $policy_name match from-zone $src_zone to-zone $dst_zone\n";
        print
          "set security policies global policy p_$policy_name then $action\n";
        push @srx_config,
"set security policies global policy $policy_name match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        push @srx_config,
"set security policies global policy $policy_name match from-zone $src_zone to-zone $dst_zone\n";
        push @srx_config,
          "set security policies global policy $policy_name then $action\n";
    }
    elsif ( !defined( $src_zone && $dst_zone )
        && ( @src_address && @dst_address && @application )
        && defined $action )
    {
        print
"set security policies global policy $policy_name match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print
          "set security policies global policy p_$policy_name then $action\n";
        push @srx_config,
"set security policies global policy $policy_name match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        push @srx_config,
          "set security policies global policy $policy_name then $action\n";
    }

    # if ( ( @hillstone_config && @srx_config ) && defined $opt_c ) {
    #     set_compare( \@hillstone_config, \@srx_config );
    # }
    undef $src_zone;
    undef $dst_zone;
    undef @src_address;
    undef @dst_address;
    undef @application;
    undef $action;
    return;
}

# first cycle for address, service, rule, interface, zone

BEGIN {
    if ( $#ARGV < 0 || $#ARGV > 5 ) {
        die "\nUsage:\tperl hw2srx.pl <config.file>\n";
    }

    if ( system("/usr/bin/dos2unix $ARGV[0]") != 0 ) {
        print "command failed!: dos2unix:\n";
        exit;
    }

# save all content of config to a variable, we will process the variable instead of <>
    open my $config, '<', $ARGV[0]
      or die "can't open file:$!\n";    #open the config filehandle
    $text = do { local $/; <$config> };
    close $config;
}

# replace the ssg's predefine services with srx's predefine applications
while ( ( $key, $value ) = each %huawei_srx_services ) {
    $text =~ s/\b$key\b/$value/gm;
}

$text =~ s!\baction .*\b!$&\nexit!gm;    # 在action下一行添加exit,用于set_polices识别
@texts = split( /\n/, $text );

# s/^\s+//g for @texts;                    # 去除开头空白
map { s/^\s+//g } @texts;

while ( $texts[$n] ) {
    if ( $texts[$n] =~ /\brule name\b/ ) {

        # 删除双引号之间的空白字符
        $texts[$n] =~ s{(?<=")(\S+)\s+}{$1_}g;

        # $texts[$n] =~ s{".*?"}{$& =~ y/ /_/r}ge; or
        # $texts[$n] =~ /(?<=")(\S+)\s+/p;
        # print $texts[$n], "\n";
    }

    my @configs = split /\s+/, $texts[$n];

    if ( $configs[0] eq "rule" ) {
        set_polices( $configs[-1] );
    }
    $n++;
}

END {
    # 去重
    my @add_source_address = do {
        my %tmp_src;
        grep { !$tmp{$_}++ } @set_source_address;
    };

    my @add_destination_address = do {
        my %tmp_src;
        grep { !$tmp{$_}++ } @set_destination_address;
    };
    print "$_\n" foreach @set_source_address;
    print "$_\n" foreach @add_destination_address;
}
