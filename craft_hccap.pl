#!/usr/bin/env perl

# Author: philsmd
# License: public domain
# First released: January 2015

use strict;
use warnings;

#
# Constants
#

my $DEFAULT_OUTFILE = "m02500.hccap";

#
# Helper functions
#

sub usage ()
{
  print "usage: $0 [OPTIONS]\n\n";

  print "where the available OPTIONS are:\n";
  print "-h | --help          show this usage information\n";
  print "-o | --outfile       output file (default is $DEFAULT_OUTFILE)\n";
  print "-e | --essid         ESSID of the access point\n";
  print "-b | --bssid         BSSID of the access point\n";
  print "-m | --mac           MAC address of the client\n";
  print "-s | --snonce        nonce-value (random salt) send by the client\n";
  print "-a | --anonce        nonce-value (random salt) send by the access point\n";
  print "-E | --eapol         EAPOL\n";
  print "-S | --eapol-size    length of the EAPOL\n";
  print "-v | --key-version   WPA key version, 1 = WPA, other = WPA2\n";
  print "-k | --key-mic       MD5 or SHA1 hash value, depending on the key version (truncated to 16 bytes)\n\n";

  print "NOTE: all arguments except --help and --outfile can be repeated multiple times, if you want to craft a .hccap\n";
  print "file which contains several networks (i.e. which contains several hccap files, a so-called mutli hccap file)\n";
}

sub is_valid_hex
{
  my $hex = shift;
  my $min = shift;
  my $max = shift;

  my $ret = 0;

  $$hex =~ s/[: ]//g;

  if ($$hex =~ m/^[0-9a-fA-F]{$min,$max}$/)
  {
    $ret = 1;
  }

  $$hex = lc ($$hex);

  return $ret;
}

sub check_essid
{
  my $essid = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (length ($essid) < 1)
  {
    $$error_msg = "ESSID is too short, it must be at least of length 1";

    $ret = 0;
  }

  if (length ($essid) > 32)
  {
    $$error_msg = "ESSID '$essid' is too long, it can't be longer than 32 characters long";

    $ret = 0;
  }

  return $ret;
}

sub check_mac_address
{
  my $mac = shift;
  my $error_msg = shift;

  my $ret = 1;

  my $mac_orig = $$mac;

  if (! is_valid_hex ($mac, 12, 12))
  {
    $$error_msg = "'$mac_orig' is not a valid MAC address, it must be of this hexadecimal format: [a-fA-F0-9]{12}";

    $ret = 0;
  }

  return $ret;
}

sub check_nonce
{
  my $nonce = shift;
  my $error_msg = shift;

  my $ret = 1;

  my $nonce_orig = $$nonce;

  if (! is_valid_hex ($nonce, 64, 64))
  {
    $$error_msg = "'$nonce_orig' is not a valid nonce value, it must be of hexadecimal format: [a-fA-f0-9]{64}";

    $ret = 0;
  }

  return $ret;
}

sub check_eapol
{
  my $eapol = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (! is_valid_hex ($eapol, 2, 512))
  {
    $$error_msg = "the EAPOL is not in the correct hexadecimal format: [a-fA-F0-9]{2, 512}";

    $ret = 0;
  }

  return $ret;
}

sub check_eapol_size
{
  my $eapol_size = shift;
  my $error_msg  = shift;

  my $ret = 1;

  if (length ($eapol_size) < 1)
  {
    $$error_msg = "the EAPOL size is too small";

    $ret = 0;
  }
  else
  {
    if ($eapol_size < 1)
    {
      $$error_msg = "the EAPOL size is too small";

      $ret = 0;
    }
    elsif ($eapol_size > 255)
    {
      $$error_msg = "the EAPOL size is too large";

      $ret = 0;
    }
  }

  return $ret;
}

sub check_key_version
{
  my $version = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (length ($version) < 1)
  {
    $$error_msg = "the WPA key '$version' is not numeric";

    $ret = 0;
  }
  else
  {
    if ($version !~ m/^[0-9]+$/)
    {
      $$error_msg = "the WPA key '$version' is not numeric";

      $ret = 0;
    }

    if ($version < 1)
    {
      $$error_msg = "the WPA key version must be at least 1";

      $ret = 0;
    }
    elsif (($version != 1) && ($version != 2))
    {
      print "WARNING: the WPA key version should normally be either 1 or 2";
    }
  }

  return $ret;
}

sub check_key_mic
{
  my $mic = shift;
  my $error_msg = shift;

  my $ret = 1;

  my $mic_orig = $$mic;

  if (! is_valid_hex ($mic, 32, 32))
  {
    $$error_msg = "the WPA key mic '$mic_orig' is not in the correct hexadecimal format: [a-fA-F0-9]{32}";

    $ret = 0;
  }

  return $ret;
}

sub add_item
{
  my $hccaps = shift;
  my $type   = shift;
  my $value  = shift;

  $hccaps->{$type} = $value;
}

sub check_item
{
  my $type = shift;
  my $value = shift;
  my $error_msg = shift;

  my $ret = 0;

  if ($type eq "essid")
  {
    $ret = check_essid ($$value, $error_msg);
  }
  elsif ($type eq "bssid")
  {
    $ret = check_mac_address ($value, $error_msg);
  }
  elsif ($type eq "mac")
  {
    $ret = check_mac_address ($value, $error_msg);
  }
  elsif ($type eq "snonce")
  {
    $ret = check_nonce ($value, $error_msg);
  }
  elsif ($type eq "anonce")
  {
    $ret = check_nonce ($value, $error_msg);
  }
  elsif ($type eq "eapol")
  {
    $ret = check_eapol ($value, $error_msg);
  }
  elsif ($type eq "eapol_size")
  {
    $ret = check_eapol_size ($$value, $error_msg);
  }
  elsif ($type eq "key_version")
  {
    $ret = check_key_version ($$value, $error_msg);
  }
  elsif ($type eq "key_mic")
  {
    $ret = check_key_mic ($value, $error_msg);
  }

  return $ret;
}

sub create_new_item
{
  my %new_hccap_item =
  (
    essid => "",
    bssid => "",
    mac => "",
    snonce => "",
    anonce => "",
    eapol => "",
    eapol_size => "",
    key_version => "",
    key_mic => ""
  );
  return \%new_hccap_item;
}

sub add_to_hccaps
{
  my $hccaps = shift;
  my $input_type  = shift;
  my $input_value = shift;

  my $found = 0;
  my $count = 1;

  foreach my $key (keys %$hccaps)
  {
    if (length ($hccaps->{$key}{$input_type}) < 1)
    {
      add_item ($hccaps->{$key}, $input_type, $input_value);

      $found = 1;

      last;
    }

    $count++;
  }

  # if not found, add a new set of items

  if ($found == 0)
  {
    $hccaps->{$count} = create_new_item ();

    add_item ($hccaps->{$count}, $input_type, $input_value);
  }
}

# return values:
# 0 -> everything is okay
# 1 -> empty (no arguments supplied)
# 2 -> error

sub check_hccaps
{
  my $hccaps = shift;
  my $error_msg = shift;

  my $ret = 1;

  my $length = scalar (keys %$hccaps);

  if ($length == 0)
  {
    $ret = 1;
  }
  else
  {
    foreach my $item (keys %$hccaps)
    {
      foreach my $key (keys $hccaps->{$item})
      {
        if (! check_item ($key, \$hccaps->{$item}{$key}, $error_msg))
        {
          if (length ($hccaps->{$item}{$key}) < 1)
          {
            $$error_msg = "$key was not set for network number $item";
          }

          $ret = 2;
        }

        last if ($ret == 2);
      }

      last if ($ret == 2);
    }

    # everything was okay if not 2
    $ret = 0 if ($ret != 2);
  }

  return $ret;
}

sub get_user_input
{
  my $msg = shift;

  print $msg;

  my $input = <STDIN>;

  chomp ($input);

  return $input;
}

sub get_interactive_input
{
  my $hccaps = shift;

  my $count = 1;

  my $error_msg = "";
  my $msg = "";

  while (1)
  {
    # should we continue to ask the user for the inputs

    if ($count > 1)
    {
      $msg = "Would you like further networks [y/N]? ";

      my $answer = get_user_input ($msg);

      if ($answer !~ m/^[yY]/)
      {
        last;
      }
    }

    $hccaps->{$count} = create_new_item ();

    # essid
    my $essid;
    $msg = "Please specify the network name (ESSID): ";

    $essid = get_user_input ($msg);

    while (! check_item ("essid", \$essid, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $essid = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "essid", $essid);

    # bssid
    my $bssid;
    $msg = "Please specify the access point MAC (BSSID) in hex: ";

    $bssid = get_user_input ($msg);

    while (! check_item ("bssid", \$bssid, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $bssid = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "bssid", $bssid);

    # mac (of client)
    my $mac;
    $msg = "Please specify the client MAC address in hex: ";

    $mac = get_user_input ($msg);

    while (! check_item ("mac", \$mac, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $mac = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "mac", $mac);

    # snonce
    my $snonce;
    $msg = "Please input the clients nonce-value (snonce), 64 hex characters: ";

    $snonce = get_user_input ($msg);

    while (! check_item ("snonce", \$snonce, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $snonce = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "snonce", $snonce);

    # anonce
    my $anonce;
    $msg = "Please input the access point nonce-value (anonce), 64 hex characters: ";

    $anonce = get_user_input ($msg);

    while (! check_item ("anonce", \$anonce, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $anonce = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "anonce", $anonce);

    # eapol size
    my $eapol_size;
    $msg = "Please specify the size of EAPOL: ";

    $eapol_size = get_user_input ($msg);

    while (! check_item ("eapol_size", \$eapol_size, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $eapol_size = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "eapol_size", $eapol_size);

    # eapol
    my $eapol;
    $msg = "Please input the full EAPOL in hex: ";

    $eapol = get_user_input ($msg);

    while (! check_item ("eapol", \$eapol, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $eapol = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "eapol", $eapol);

    # key version
    my $key_version;
    $msg = "Please specify the WPA version (1 = WPA, 2 = WPA2): ";

    $key_version = get_user_input ($msg);

    while (! check_item ("key_version", \$key_version, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $key_version = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "key_version", $key_version);

    # key mic
    my $key_mic;
    $msg = "Please specify the key mic (the MD5 or truncated SHA1 hash), 32 hex characters: ";

    $key_mic = get_user_input ($msg);

    while (! check_item ("key_mic", \$key_mic, \$error_msg))
    {
      if ($error_msg)
      {
        print "ERROR: $error_msg\n";
      }

      $key_mic = get_user_input ($msg);
    }

    add_item ($hccaps->{$count}, "key_mic", $key_mic);

    $count++;
  }
}

sub write_hccap
{
  my $fp = shift;
  my $hccaps = shift;

  foreach my $item (keys %$hccaps)
  {
    # first to output is:

    # essid
    my $essid = $hccaps->{$item}{essid};
    my $essid_length = length ($essid);

    if ($essid_length > 32) # shouldn't be possible but you never know
    {
      $essid_length = 32;
    }

    my $essid_padding_length = 36 - $essid_length;

    print $fp substr ($essid, 0, 32) . ("\x00" x $essid_padding_length);

    # bssid
    my $bssid = $hccaps->{$item}{bssid};
    my $bssid_bin = pack ("H*", $bssid);

    print $fp substr ($bssid_bin, 0, 8);

    # mac (of client)
    my $mac = $hccaps->{$item}{mac};
    my $mac_bin = pack ("H*", $mac);

    print $fp substr ($mac_bin, 0, 8);

    # snonce
    my $snonce = $hccaps->{$item}{snonce};
    my $snonce_bin = pack ("H*", $snonce);

    print $fp substr ($snonce_bin, 0, 32);

    # anonce
    my $anonce = $hccaps->{$item}{anonce};
    my $anonce_bin = pack ("H*", $anonce);

    print $fp substr ($anonce_bin, 0, 32);

    # get eapol size
    my $eapol_size = $hccaps->{$item}{eapol_size};

    # eapol
    my $eapol = $hccaps->{$item}{eapol};
    my $eapol_bin = pack ("H*", $eapol);
    my $eapol_padding_length = 256 - $eapol_size;

    print $fp substr ($eapol_bin, 0, $eapol_size) . ("\x00" x $eapol_padding_length);

    # eapol size
    my $eapol_size_little_endian = pack ("L*", $eapol_size);

    print $fp substr ($eapol_size_little_endian, 0, 4);

    # key version
    my $key_version = $hccaps->{$item}{key_version};
    my $key_version_little_endian = pack ("L*", $key_version);

    print $fp substr ($key_version_little_endian, 0, 4);

    # key mic
    my $key_mic = $hccaps->{$item}{key_mic};
    my $key_mic_bin = pack ("H*", $key_mic);

    print $fp substr ($key_mic_bin, 0, 16);
  }
}

#
# START
#

my $outfile = "";

my $arg_size = scalar (@ARGV);

my %hccap_contents = ();


my $switch = "";

foreach my $arg (@ARGV)
{
  if ($switch ne "")
  {
    if ($switch eq "outfile") 
    {
      $outfile = $arg;
    }
    elsif ($switch eq "essid") 
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "bssid")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "mac")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "snonce")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "anonce")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "eapol")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "eapol_size")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "key_version")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }
    elsif ($switch eq "key_mic")
    {
      add_to_hccaps (\%hccap_contents, $switch, $arg);
    }

    $switch = "";
  }
  else
  {
    if (($arg eq "-h") || ($arg eq "--help"))
    {
      usage ();

      exit (0);
    }
    elsif (($arg eq "-o") || ($arg eq "--outfile"))
    {
      $switch = "outfile";
    }
    elsif (($arg eq "-e") || ($arg eq "--essid"))
    {
      $switch = "essid";
    }
    elsif (($arg eq "-b") || ($arg eq "--bssid"))
    {
      $switch = "bssid";
    }
    elsif (($arg eq "-m") || ($arg eq "--mac"))
    {
      $switch = "mac";
    }
    elsif (($arg eq "-s") || ($arg eq "--snonce"))
    {
      $switch = "snonce";
    }
    elsif (($arg eq "-a") || ($arg eq "--anonce"))
    {
      $switch = "anonce";
    }
    elsif (($arg eq "-E") || ($arg eq "--eapol"))
    {
      $switch = "eapol";
    }
    elsif (($arg eq "-S") || ($arg eq "--eapol-size"))
    {
      $switch = "eapol_size";
    }
    elsif (($arg eq "-v") || ($arg eq "--key-version"))
    {
      $switch = "key_version";
    }
    elsif (($arg eq "-k") || ($arg eq "--key-mic"))
    {
      $switch = "key_mic";
    }
    else
    {
      print "ERROR: unknown command line argument. Please check the usage: \n\n";

      usage ();

      exit (1);
    }
  }
}

# check if hccap_contents was correctly set

my $error_msg = "";
my $check = check_hccaps (\%hccap_contents, \$error_msg);

if ($check == 1)
{
  get_interactive_input (\%hccap_contents);

  my $check_again = check_hccaps (\%hccap_contents, \$error_msg);

  if ($check_again != 0)
  {
    if (length ($error_msg))
    {
      print "ERROR: $error_msg\n";
    }
    else
    {
      print "ERROR: an unexpected error occurred\n";
    }

    exit (1);
  }
}
elsif ($check == 2)
{
  # not empty, but we have detected some error(s)

  print "ERROR: $error_msg\n";

  exit (1);
}


# output file handling

my $fp;

if ($outfile eq "")
{
  $outfile = $DEFAULT_OUTFILE;

  my $warning_shown = 0;

  while (-e $outfile)
  {
    $outfile .= "_new.hccap";

    if ($warning_shown == 0)
    {
      print "WARNING: the default output file does already exist, it won't be overriden therefore '$outfile' is used as outfile\n";
      print "(if you want to disable this behavior you should set the --outfile argument)\n";

      $warning_shown = 1;
    }
  }
}

if (! open ($fp, ">$outfile"))
{
  print "ERROR: could not open the output file '$outfile'\n";

  exit (1);
}

# write to hccap file

write_hccap ($fp, \%hccap_contents);

# done / cleanup

print ".hccap file '$outfile' was successfully written\n";

close ($fp);

exit (0);
