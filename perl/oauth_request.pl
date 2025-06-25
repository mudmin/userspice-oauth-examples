#!/usr/bin/perl
# Perl Vanilla OAuth Client Example for UserSpice
# Simulates initiating the OAuth request

use strict;
use warnings;
use LWP::UserAgent; # For making HTTP requests (though not used directly here, good practice for response)
use URI;
use URI::Escape;
use Digest::MD5 qw(md5_hex); # Simple way to get a somewhat random string for state

# Assuming oauth_config.pl is in the same directory or in @INC
require "oauth_config.pl";
my $settings = get_oauth_settings();

my $authorization_endpoint = $settings->{server_url} . $settings->{auth_endpoint_path};

# Generate a state parameter for CSRF protection
# Using time and a random number, then hashing for simplicity. UUID module would be better.
my $state = md5_hex(time() . rand() . $$);
# In a real web app, you would store this 'state' in the user's session
# to verify it on callback.
print "Generated state (should be stored in session): $state\n";

# Build the authorization URL
my $auth_uri = URI->new($authorization_endpoint);
$auth_uri->query_form(
    response_type => 'code',
    client_id     => $settings->{client_id},
    redirect_uri  => $settings->{redirect_uri},
    state         => $state,
    scope         => 'profile', # Add any scopes you need
);

my $auth_url = $auth_uri->as_string;

print "\n--- OAuth Authorization Request Simulation (Perl) ---\n";
print "In a real web application, you would redirect the user to the following URL:\n";
print "$auth_url\n";
print "\nAfter the user authorizes, they will be redirected to your redirect_uri with a 'code' and 'state' parameter.\n";
print "Example: $settings->{redirect_uri}?code=AUTHORIZATION_CODE_HERE&state=$state\n";

exit 0;
