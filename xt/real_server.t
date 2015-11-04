use warnings;
use strict;
use XML::Compile::WSDL11;
use XML::Compile::SOAP11;
use XML::Compile::Transport::SOAPHTTP;
use Log::Report mode => 'NORMAL';
use Siebel::SOAP::Auth;
use Config::Tiny 2.23;
use Test::More tests => 3;

my ( $call, $auth );
my %request = (
    ListOfSwicontactio => {
        Contact => {
            Id        => '0-1',
            FirstName => 'Siebel',
            LastName  => 'Administrator'
        }
    }
);

SKIP: {

    skip 'No configuration available for testing with a real server', 3
      unless ( ( exists( $ENV{SIEBEL_SOAP_AUTH} ) )
        and ( defined( $ENV{SIEBEL_SOAP_AUTH} ) ) );

    my $config = Config::Tiny->read( $ENV{SIEBEL_SOAP_AUTH} );
    my $wsdl   = XML::Compile::WSDL11->new( $config->{General}->{wsdl} );
    my $auth   = Siebel::SOAP::Auth->new(
        {
            user     => $config->{General}->{user},
            password => $config->{General}->{password}
        }
    );
    $call = $wsdl->compileClient(
        operation      => 'SWIContactServicesQueryByExample',
        transport_hook => \&run
    );

    my ( $answer, $trace ) = $call->(%request);
    my $answer_ok = 0;
    if ( my $e = $@->wasFatal ) {

        BAIL_OUT($e);

    }
    else {

        $answer_ok = 1;

    }
    ok( $answer_ok, 'Siebel Servers answer is OK' );
    is( ref($answer), 'HASH',
        'the answer returned from the Siebel Server is valid' );
    $auth->find_token($answer);
    isnt( $auth->get_token, 'unset', 'the Siebel Server returned a token' );

}

# :TODO:04-11-2015 10:30:56:: must implement the validation of token expiration
#while (1) {
#
#    try sub {
#
#        sleep( int( rand(11) ) + 10 );
#        my ( $answer, $trace ) = $call->(%request);
#        $auth->find_token($answer);
#
#    };
#
#    if ( my $e = $@->wasFatal ) {
#
#        if ( $e =~ /token expired/ ) {
#
#            die
#'Server returned an error due token expiration, check remain_ttl attribute value ( was: '
#              . $auth->get_remain_ttl . ')';
#
#        }
#        else {
#
#            $e->throw;
#
#        }
#    }
#
#}

sub run {

    my ( $request, $trace, $transporter ) = @_;
    my $answer =
      $trace->{user_agent}->request( $auth->add_auth_header($request) );
    return $answer;

}
