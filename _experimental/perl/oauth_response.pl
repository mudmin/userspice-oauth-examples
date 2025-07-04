#!/usr/bin/perl
# Perl Vanilla OAuth Client Example for UserSpice
# Simulates handling the OAuth response and exchanging code for a token

use strict;
use warnings;
use LWP::UserAgent;
use URI;
use JSON; # For parsing JSON response - common module, may need install (cpan JSON)

# Assuming oauth_config.pl is in the same directory or in @INC
require "oauth_config.pl";
my $settings = get_oauth_settings();

print "--- OAuth Token Exchange Simulation (Perl) ---\n";

# Simulate receiving the authorization code and state from the redirect
# In a real CGI/web app, you'd get these from query parameters (e.g., using CGI module)
print "Enter the 'code' received from UserSpice: ";
my $auth_code = <STDIN>;
chomp $auth_code;

print "Enter the 'state' received from UserSpice (must match the one generated in oauth_request.pl): ";
my $received_state = <STDIN>;
chomp $received_state;

# Simulate retrieving the original state from session. For this example, we'll just prompt for it.
print "Enter the original 'state' you stored (from oauth_request.pl output): ";
my $original_state = <STDIN>;
chomp $original_state;

unless ($auth_code && length $auth_code > 0) {
    die "Error: No authorization code received.\n";
}

unless ($received_state && $received_state eq $original_state) {
    die "Error: Invalid state parameter. CSRF attack suspected or state mismatch.\nReceived: $received_state, Original: $original_state\n";
}
print "State verified successfully.\n";

# Exchange the authorization code for an access token
my $token_url_string = $settings->{server_url} . $settings->{token_endpoint_path};

my $ua = LWP::UserAgent->new;
$ua->timeout(10); # Set a timeout

my %post_data = (
    grant_type    => 'authorization_code',
    code          => $auth_code,
    redirect_uri  => $settings->{redirect_uri},
    client_id     => $settings->{client_id},
    client_secret => $settings->{client_secret},
);

my $response = $ua->post($token_url_string, \%post_data);

print "\nToken Exchange Response (HTTP " . $response->code . "):\n";
if ($response->is_success) {
    print $response->decoded_content . "\n"; # Assumes text/JSON response
    print "\nAuthentication successful!\n";

    # Attempt to parse JSON if available
    eval {
        my $json_data = decode_json($response->decoded_content);
        if ($json_data->{access_token}) {
            print "Access Token: " . $json_data->{access_token} . "\n";
        }
    };
    if ($@) {
        print "Could not parse JSON from response, or access_token not found: $@\n";
    }

    print "\nYour login function here. You can now use the access token to make authenticated requests to UserSpice API.\n";
} else {
    print "Failed to exchange code for token.\n";
    print "Status: " . $response->status_line . "\n";
    print "Content: " . $response->decoded_content . "\n" if $response->decoded_content;
}

exit 0;
