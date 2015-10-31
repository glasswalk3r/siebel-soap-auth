package Siebel::SOAP::Auth;

use strict;
use warnings;
use Moo 2.000001;
use Types::Standard 1.000005 qw(Str Int RegexpRef Num);
use XML::LibXML 2.0115;
use namespace::clean 0.25;
use Encode qw(encode);
use Scalar::Util qw(blessed);
use Time::HiRes qw(time);
use Log::Report 1.05 'siebel-soap-auth', syntax => 'SHORT';

=pod

=head1 NAME

Siebel::SOAP::Auth - Moo based class to implement transparent Siebel Session Management for XML::Compile::WSDL11

=cut

has token_key => ( is => 'lazy', isa => Str, reader => 'get_token_key' );
has header_ns => (
    is      => 'rw',
    isa     => Str,
    default => 'http://siebel.com/webservices',
    reader  => 'get_header_ns',
    writer  => 'set_header_ns'
);
has user => (
    is       => 'rw',
    isa      => Str,
    reader   => 'get_user',
    writer   => 'set_user',
    required => 1
);
has password => (
    is       => 'rw',
    isa      => Str,
    reader   => 'get_pass',
    writer   => 'set_pass',
    required => 1
);
has token => (
    is      => 'ro',
    isa     => Str,
    reader  => 'get_token',
    writer  => '_set_token',
    default => 'unset'
);
has lookup_ns => (
    is      => 'rw',
    isa     => Str,
    default => 'http://schemas.xmlsoap.org/soap/envelope/',
    reader  => 'get_lookup_ns',
    writer  => 'set_lookup_ns'
);
has remain_ttl =>
  ( is => 'ro', isa => Int, default => 10, reader => 'get_remain_ttl' );
has session_type => (
    is      => 'ro',
    isa     => Str,
    reader  => 'get_session_type',
    default => 'Stateless'
);
has last_fault => (
    is     => 'ro',
    isa    => Str,
    reader => 'get_last_fault',
    writer => '_set_last_fault'
);
has auth_fault => (
    is      => 'ro',
    isa     => RegexpRef,
    reader  => 'get_auth_fault',
    default => sub { qr/^Error\sCode:\s10944642/ }
);
has session_timeout =>
  ( is => 'ro', isa => Int, default => 900, reader => 'get_session_timeout' );
has token_timeout =>
  ( is => 'ro', isa => Int, default => 900, reader => 'get_token_timeout' );
has token_max_age =>
  ( is => 'ro', isa => Int, default => 172800, reader => 'get_token_max_age' )
  ;    # 2880 minutes
has _token_birth => (
    is        => 'ro',
    isa       => Num,
    reader    => '_get_token_birth',
    writer    => '_set_token_birth',
    predicate => 1,
    clearer   => 1
);

sub _build_token_key {

    my ($self) = @_;
    return '{' . $self->get_header_ns() . '}SessionToken';

}

sub add_auth_header {

    #my ($self, $request, $ua) = @_;
    my ( $self, $request ) = @_;

    die "Expect as parameter a HTTP::Request instance"
      unless ( ( defined($request) )
        and ( defined( blessed($request) ) )
        and ( $request->isa('HTTP::Request') ) );

#die "Expect as parameter a LWP::UserAgent object" unless ( (defined($ua)) and (defined(blessed($ua))) and ($ua->isa('LWP::UserAgent')) );

    my $payload = XML::LibXML->load_xml( string => $request->decoded_content );
    my $root    = $payload->getDocumentElement;
    my $prefix  = $root->lookupNamespacePrefix( $self->get_lookup_ns() );
    my $soap_header = $payload->createElement( $prefix . ':Header' );
    my %auth;

    if ( $self->get_token() ne 'unset' ) {

# how long the token is around plus the acceptable remaining seconds to be reused
        my $token_age =
          time() - $self->_get_token_birth() + $self->get_remain_ttl();
        trace "token age is $token_age";

        if (    ( $token_age < $self->get_token_max_age() )
            and ( $token_age < $self->get_session_timeout() )
            and ( $token_age < $self->get_token_timeout() ) )
        {

            %auth = (
                SessionToken => $self->get_token(),
                SessionType  => $self->get_session_type()
            );
            trace 'using acquired session token';

        }
        else {

            trace 'preparing to request a new session token';
            %auth = (
                SessionType   => $self->get_session_type(),
                UsernameToken => $self->get_user(),
                PasswordText  => $self->get_pass()
            );
            $self->_set_token('unset');    # sane setting
            $self->_clear_token_birth();
            trace 'cleaned up token and token_birth attributes';

        }

    }
    else {

        %auth = (
            SessionType   => $self->get_session_type(),
            UsernameToken => $self->get_user(),
            PasswordText  => $self->get_pass()
        );

    }

    my $ns = $self->get_header_ns();

    # WORKAROUND: sort is used to make it easier to test the request assembly
    foreach my $element_name ( sort( keys(%auth) ) ) {

        my $child = $payload->createElementNS( $ns, $element_name );
        $child->appendText( $auth{$element_name} );
        $soap_header->appendChild($child);

    }

    $root->insertBefore( $soap_header, $root->firstChild );

    my $new_content = encode( 'UTF-8', $root );
    $request->header( Content_Length => length($new_content) );
    $request->content($new_content);
    return $request;

}

sub find_token {

    my ( $self, $answer ) = @_;

    die "Expect as parameter a hash reference"
      unless ( ( defined($answer) ) and ( ref($answer) eq 'HASH' ) );

    my $key = $self->get_token_key();

    if ( exists( $answer->{$key} ) ) {

        die "Expect as parameter a XML::LibXML::Element instance"
          unless ( ( defined( $answer->{$key} ) )
            and ( defined( blessed( $answer->{$key} ) ) )
            and ( $answer->{$key}->isa('XML::LibXML::Element') ) );
        $self->_set_token( $answer->{$key}->textContent );
        $self->_set_token_birth( time() ) unless ( $self->_has_token_birth );

    }
    else {

        die "could not find the key $key in the answer received as parameter";

    }

}

sub check_fault {

    my ( $self, $answer ) = @_;

    if ( exists( $answer->{Fault} ) ) {

        if ( $answer->{Fault}->{faultstring} =~ $self->get_auth_fault() ) {

            die 'token expired';

        }
        else {

            die $answer->{Fault}->{faultstring};

        }

    }

}

1;
