# Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# IdastDBPlugin is Copyright (C) 2016 Chris Hoefler http://draper.com/
#

use strict;
use warnings;
use 5.014;

package Foswiki::Plugins::JsonSQLPlugin;

use Foswiki::Func    ();    # The plugins API
use Foswiki::Plugins ();    # For the API version

use JsonSQL::Query::Select;
use JsonSQL::Query::Insert;
use JsonSQL::Validator;

use DBI;
use JSON qw( encode_json decode_json to_json from_json );

#use Data::Dumper;
#use constant DEBUG => 1;    # toggle me

our $VERSION = '0.4';
our $RELEASE = '01 Aug 2017';
our $SHORTDESCRIPTION = 'Provides JSON handlers for interacting with SQL databases';
our $NO_PREFS_IN_TOPIC = 1;

sub initPlugin {
    my ( $topic, $web, $user, $installWeb ) = @_;

    # check for Plugins.pm versions
    if ( $Foswiki::Plugins::VERSION < 2.3 ) {
        Foswiki::Func::writeWarning( 'Version mismatch between ',
            __PACKAGE__, ' and Plugins.pm' );
        return 0;
    }

    # JsonRpc Handlers
    Foswiki::Contrib::JsonRpcContrib::registerMethod( "jsondb", "select", \&jsondbget );
    Foswiki::Contrib::JsonRpcContrib::registerMethod( "jsondb", "selectwithsearch", \&jsondbgetandsearch );
    Foswiki::Contrib::JsonRpcContrib::registerMethod( "jsondb", "insert", \&jsondbinsert );

    return 1;
}

=pod PrivateMethod _dbConnect($dbname, $queryop) -> $dbh

First parses the $Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbusermap} configuration setting to identify the correct DB user and pass to
use for connecting to the DB indicated by $dbname and performing the operation indicated by $opname.

Then parses the $Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbconnections} configuration setting, first identifying the DB namespace entry
indicated by $dbname, and then establishing a DB connection using the dsn property of the DB namespace and the previously found DB username
and password.

Returns a Perl DBI database handle if successful, or (0, <err msg>) if it fails.

=cut

sub _dbConnect {
    my ( $dbname, $queryop ) = @_;

    return ( 0, "No DB namespace specified." ) unless $dbname;

    my $connhash = $Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbconnections};
    my $usermap  = $Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbusermap};

    my $db_user;
    my $db_pass;
    if ( $usermap && ref($usermap) eq 'ARRAY' ) {
        my $user = Foswiki::Func::getWikiName();

        # First check Foswiki groups.
        my @group_acls = grep {
                 exists( $_->{allowedGroup} )
              && Foswiki::Func::isGroup( $_->{allowedGroup} )
              && Foswiki::Func::isGroupMember( $_->{allowedGroup}, $user )
              && exists( $_->{$dbname} )
        } @{$usermap};

        # This will go in order through @group_acls. Later definitions will override earlier definitions.
        for my $groupdef (@group_acls) {
            if ( $queryop && exists( $groupdef->{$dbname}->{$queryop} ) ) {
                $db_user = $groupdef->{$dbname}->{$queryop}->{user};
                $db_pass = $groupdef->{$dbname}->{$queryop}->{pass};
            }
            elsif ( exists( $groupdef->{$dbname}->{default} ) ) {
                $db_user = $groupdef->{$dbname}->{default}->{user};
                $db_pass = $groupdef->{$dbname}->{default}->{pass};
            }
        }

        # Now check Foswiki users. This allows users to override groups.
        my @user_acls = grep {
                 exists( $_->{allowedUser} )
              && $_->{allowedUser} eq $user
              && exists( $_->{$dbname} )
        } @{$usermap};

        for my $userdef (@user_acls) {
            if ( $queryop && exists( $userdef->{$dbname}->{$queryop} ) ) {
                $db_user = $userdef->{$dbname}->{$queryop}->{user};
                $db_pass = $userdef->{$dbname}->{$queryop}->{pass};
            }
            elsif ( exists( $userdef->{$dbname}->{default} ) ) {
                $db_user = $userdef->{$dbname}->{default}->{user};
                $db_pass = $userdef->{$dbname}->{default}->{pass};
            }
        }
    }

    if ( $db_user && $db_pass ) {
        if (   $connhash
            && ref($connhash) eq 'HASH'
            && exists( $connhash->{$dbname} ) )
        {
            my $dsn = $connhash->{$dbname}->{dsn};
            my $dbh =
              DBI->connect( $dsn, $db_user, $db_pass,
                { AutoCommit => 1, RaiseError => 1, PrintError => 0 } );
            return $dbh if $dbh;
            return ( 0, "Could not establish DB connection: $DBI::errstr." );
        }
        else {
            return ( 0, "No DB connections defined for $dbname." );
        }
    }
    else {
        return ( 0,
            "No DB credentials found for the currently logged in user." );
    }
}

=pod PrivateMethod _checkAcl($dbname, $queryop) -> $whitelist_rules

Parses the $Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbconnections} configuration setting, first identifying the DB namespace entry
indicated by $dbname, then the set of whitelist rules to be applied for a give Foswiki user/group and DB operation combination.

Returns an arrayref of whitelist rules for use with JsonSQL if successful, or (0, <err msg>) if it fails.

=cut

sub _checkAcl {
    my ( $dbname, $queryop ) = @_;

    return ( 0, "No DB namespace specified." ) unless $dbname;

    my $connhash = $Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbconnections};

    my $whitelist_rules;
    if (   $connhash
        && ref($connhash) eq 'HASH'
        && exists( $connhash->{$dbname} ) )
    {
        my $user = Foswiki::Func::getWikiName();

        my $opkey = 'allowDefault';
        for ($queryop) {
            when ('select') { $opkey = "allowSelect"; }
            when ('insert') { $opkey = "allowInsert"; }
        }

#        Foswiki::Func::writeDebug("User: $user")   if DEBUG;
#        Foswiki::Func::writeDebug("OpKey: $opkey") if DEBUG;

        if ( exists( $connhash->{$dbname}->{$opkey} ) ) {
#            Foswiki::Func::writeDebug( "Conn Hash: " . Dumper( $connhash->{$dbname}->{$opkey} ) ) if DEBUG;

            # First check Foswiki groups
            my @acl_keys = grep {
                     exists( $_->{allowedGroup} )
                  && Foswiki::Func::isGroup( $_->{allowedGroup} )
                  && Foswiki::Func::isGroupMember( $_->{allowedGroup}, $user )
            } @{ $connhash->{$dbname}->{$opkey} };

#            Foswiki::Func::writeDebug( "Group ACL Keys: " . Dumper(@acl_keys) ) if DEBUG;

            # This will go in order through @acl_keys. Later definitions will override earlier definitions.
            for my $acl_key (@acl_keys) {
                if ( exists( $acl_key->{whitelist_rules} ) ) {
                    $whitelist_rules = $acl_key->{whitelist_rules};
                }
            }

            # Now check Foswiki users. This allows users to override groups.
            @acl_keys =
              grep { exists( $_->{allowedUser} ) && $_->{allowedUser} eq $user }
              @{ $connhash->{$dbname}->{$opkey} };

#            Foswiki::Func::writeDebug( "User ACL Keys: " . Dumper(@acl_keys) ) if DEBUG;

            for my $acl_key (@acl_keys) {
                if ( exists( $acl_key->{whitelist_rules} ) ) {
                    $whitelist_rules = $acl_key->{whitelist_rules};
                }
            }
        }
    }
    else {
        return ( 0, "No DB connections defined for $dbname." );
    }

    if (@$whitelist_rules) {
        return $whitelist_rules;
    }
    else {
        return ( 0,
"No whitelist rules defined for $queryop access to $dbname by the currently logged in user."
        );
    }
}

=pod PrivateMethod _doSelectQuery($jsonQuery, $dbname) => \@result

Grabs the whitelist rules for the currently logged in user specified for SELECT operations on $dbname. Then generates the SQL from
$jsonQuery. If successful, continues on to grab a database handle and perform the query. The result is parsed into an arrayref sliced
as a hashref keyed to each column for each row in the result.

Returns the arrayref if successful, or (0, <err msg>) if it fails.

=cut

sub _doSelectQuery {
    my ( $jsonQuery, $dbname ) = @_;

    my ( $whitelist_rules, $err ) = _checkAcl( $dbname, 'select' );
    if ($whitelist_rules) {
#        Foswiki::Func::writeDebug( "Whitelist Rules: " . Dumper($whitelist_rules) ) if DEBUG;
        my ( $selectObj, $err ) =
          JsonSQL::Query::Select->new( $whitelist_rules, $jsonQuery );
        if ($selectObj) {
            my ( $sql, $binds ) = $selectObj->get_select;
#            Foswiki::Func::writeDebug("SQL: $sql");
#            Foswiki::Func::writeDebug( "Bind Values: " . Dumper($binds) );
            my ( $dbh, $err ) = _dbConnect( $dbname, 'select' );
            if ($dbh) {
                my $result =
                  $dbh->selectall_arrayref( $sql, { Slice => {} }, @$binds );
                $dbh->disconnect;
#                Foswiki::Func::writeDebug( "Result: " . Dumper($result) );
                return $result;
            }
            else {
                return ( 0, $err );
            }
        }
        else {
            return ( 0, $err );
        }
    }
    else {
        return ( 0, $err );
    }
}

=pod ClassMethod jsondbget($session, $request) => $json

The JSON-RPC handler for jsondb.select.

Expects jsonQuery and dbName as $request parameters. Performs the query and returns the result as encoded JSON.

Returns the stringified JSON if successful, or throws a Foswiki::Contrib::JsonRpcContrib::Error if it fails.

=cut

sub jsondbget {
    my ( $session, $request ) = @_;

    my $submittedJson = $request->param('jsonQuery');
    my $dbNamespace   = $request->param('dbName');

    my ( $queryResult, $err ) = _doSelectQuery( $submittedJson, $dbNamespace );

    throw Foswiki::Contrib::JsonRpcContrib::Error( -32603, $err )
      unless $queryResult;

    my $retJson = encode_json($queryResult);
    return $retJson;
}

=pod ClassMethod jsondbgetandsearch($session, $request) => $json

The JSON-RPC handler for jsondb.selectwithsearch.

Expects jsonQuery, dbName, and searchTopics as $request parameters. If searchTopics is not specified, this will behave like a plain
jsondbget. Performs the query, does the topic SEARCH, and merges and returns the results as encoded JSON.

Returns the stringified JSON if successful, or throws a Foswiki::Contrib::JsonRpcContrib::Error if it fails.

=cut

sub jsondbgetandsearch {
    my ( $session, $request ) = @_;

    my $submittedJson = $request->param('jsonQuery');
    my $dbNamespace   = $request->param('dbName');

    my ( $queryResult, $err ) = _doSelectQuery( $submittedJson, $dbNamespace );

    throw Foswiki::Contrib::JsonRpcContrib::Error( -32603, $err )
      unless $queryResult;

    my $searchParams = decode_json( $request->param('searchTopics') );

    for my $search ( @{$searchParams} ) {
        my $searchWeb     = $search->{web};
        my $queryString   = $search->{query};
        my $queryField    = $search->{queryField};
        my $formName      = $search->{form};
        my $topicName     = $search->{topic};
        my $formFieldName = $search->{formField};
        my $retKey        = $search->{retKey};
        my $retMany       = $search->{retMany} || 0;

        my @queryParams;
        if ( defined $queryString ) {
            push( @queryParams, $queryString );
        }
        if ( defined $formName ) {
            push( @queryParams, "form.name ~ '$formName'" );
        }
        if ( defined $topicName ) {
            push( @queryParams, "name ~ '$topicName'" );
        }
        if (@queryParams) {
            $queryString = join( " AND ", @queryParams );
        }

#        Foswiki::Func::writeDebug( Dumper(@queryParams) ) if DEBUG;
#        Foswiki::Func::writeDebug($queryString)           if DEBUG;
#        Foswiki::Func::writeDebug( Dumper($search) )      if DEBUG;

        my $topicSearchResult =
          Foswiki::Func::query( $queryString, undef, { web => $searchWeb } );

        while ( $topicSearchResult->hasNext ) {
            my $webtopic = $topicSearchResult->next;
#            Foswiki::Func::writeDebug($webtopic) if DEBUG;
            my ( $web, $topic ) =
              Foswiki::Func::normalizeWebTopicName( '', $webtopic );
            my ($meta) = Foswiki::Func::readTopic( $web, $topic );
            my $formField = $meta->get( 'FIELD', $formFieldName );

            for my $matchingRecord ( @{$queryResult} ) {
                if ( $matchingRecord->{$queryField} eq $formField->{value} ) {
                    if ($retMany) {
                        $matchingRecord->{$retKey} = []
                          if ( not defined $matchingRecord->{$retKey} );
                        push( @{ $matchingRecord->{$retKey} }, "$web.$topic" );
                    }
                    else {
                        $matchingRecord->{$retKey} = "$web.$topic";
                    }
                }
            }
        }
    }

    # Encode the result and return.
    my $retJson = encode_json($queryResult);
    return $retJson;
}

=pod ClassMethod jsondbinsert($session, $request) => $json

The JSON-RPC handler for jsondb.insert.

Grabs the whitelist rules for the currently logged in user specified for INSERT operations on dbName. Then generates the SQL for each
JSON INSERT query defined in jsonQuery. If successful, continues on to grab a database handle and perform each query. The results of batched
queries are collected in @resultsArray, and can either be a plain "# of rows" result *OR*, if the RETURNING clause feature of JsonSQL is used,
a final SELECT is done after the INSERT to get the updated table rows after the INSERT completes. The result in this case is parsed into an 
a hashref keyed to each column of the table row returned.

Returns a JSON encoded and stringified @resultsArray if successful, or throws a Foswiki::Contrib::JsonRpcContrib::Error if it fails.

=cut

sub jsondbinsert {
    my ( $session, $request ) = @_;

    my $submittedJson = $request->param('jsonQuery');
    my $dbNamespace   = $request->param('dbName');

    my ( $whitelist_rules, $err ) = _checkAcl( $dbNamespace, 'insert' );
    if ($whitelist_rules) {
        my ( $insertObj, $err ) =
          JsonSQL::Query::Insert->new( $whitelist_rules, $submittedJson );
        if ($insertObj) {
            my ( $sql, $binds ) = $insertObj->get_all_inserts;
            my ( $dbh, $err ) = _dbConnect( $dbNamespace, 'insert' );
            if ($dbh) {
                my @resultsArray;
                for my $stmtIndex ( 0 .. ( scalar( @{$sql} ) - 1 ) ) {
                    my $sth = $dbh->prepare( $sql->[$stmtIndex] );
                    my $rv  = $sth->execute( @{ $binds->[$stmtIndex] } );
                    if ( defined $rv ) {
                        if (    ( defined $sth->{NUM_OF_FIELDS} )
                            and ( $sth->{NUM_OF_FIELDS} > 0 ) )
                        {
                            my $result = $sth->fetchall_arrayref( {} );
                            push( @resultsArray, $result->[0] );
                        }
                        else {
                            push( @resultsArray, $rv );
                        }
                    }
                }

                $dbh->disconnect;
                my $retJson = encode_json( \@resultsArray );
                return $retJson;
            }
            else {
                throw Foswiki::Contrib::JsonRpcContrib::Error( -32603, $err );
            }
        }
        else {
            throw Foswiki::Contrib::JsonRpcContrib::Error( -32603, $err );
        }
    }
    else {
        throw Foswiki::Contrib::JsonRpcContrib::Error( -32603, $err );
    }
}


1;

__END__
