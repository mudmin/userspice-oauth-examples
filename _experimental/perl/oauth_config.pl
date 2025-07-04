# Perl Vanilla OAuth Client Example for UserSpice
# Configuration settings
# In a real application, this might be a .conf file or use a config module.

use strict;
use warnings;

# Subroutine to return configuration as a hash reference
sub get_oauth_settings {
    my %settings = (
        server_url        => "https://your-oauth-server.com/", # Example: "https://example.com/userspice/"
        client_id         => "your_client_id",
        client_secret     => "your_client_secret",
        redirect_uri      => "https://your_app_domain.com/oauth_response_perl", # Example: "http://localhost/callback.pl"

        auth_endpoint_path  => "usersc/plugins/oauth_server/auth.php",
        token_endpoint_path => "usersc/plugins/oauth_server/auth.php", # Often same as auth for UserSpice
    );
    return \%settings;
}

# This makes the file usable as a module or runnable to print config
if (!caller) {
    my $config = get_oauth_settings();
    print "OAuth Client Configuration (Perl):\n";
    foreach my $key (sort keys %$config) {
        print "$key: $config->{$key}\n";
    }
}

1; # Required for 'use' or 'require' to work
