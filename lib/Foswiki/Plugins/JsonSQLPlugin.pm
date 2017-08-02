# Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# IdastDBPlugin is Copyright (C) 2016 Chris Hoefler http://draper.com/
#

package Foswiki::Plugins::JsonSQLPlugin;

use strict;
use warnings;
use v5.10;    # Use for/when statement

use Foswiki::Func    ();    # The plugins API
use Foswiki::Plugins ();    # For the API version

use JsonSQL::Query::Select;
use JsonSQL::Query::Insert;
use JsonSQL::Validator;
use Data::Dumper;
use constant DEBUG => 1;    # toggle me
use DBI;
use JSON qw( encode_json decode_json to_json from_json );

our $VERSION = '0.1';
our $RELEASE = '16 Aug 2016';
our $SHORTDESCRIPTION =
  'Provides JSON handlers for interacting with SQL databases';
our $NO_PREFS_IN_TOPIC = 1;

sub initPlugin {
    my ( $topic, $web, $user, $installWeb ) = @_;

    # check for Plugins.pm versions
    if ( $Foswiki::Plugins::VERSION < 2.3 ) {
        Foswiki::Func::writeWarning( 'Version mismatch between ',
            __PACKAGE__, ' and Plugins.pm' );
        return 0;
    }

    #    Foswiki::Func::registerTagHandler( 'FORMATID', \&_formatId );

#    Foswiki::Contrib::JsonRpcContrib::registerMethod("jsontest", "select", \&jsontest);
    Foswiki::Contrib::JsonRpcContrib::registerMethod( "jsondb", "select",
        \&jsondbget );
    Foswiki::Contrib::JsonRpcContrib::registerMethod( "jsondb",
        "selectwithsearch", \&jsondbgetandsearch );

#    Foswiki::Contrib::JsonRpcContrib::registerMethod("processjson", "idtopics", \&idtotopic);
    Foswiki::Contrib::JsonRpcContrib::registerMethod( "jsondb", "insert",
        \&jsondbinsert );

    return 1;
}

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

        Foswiki::Func::writeDebug("User: $user")   if DEBUG;
        Foswiki::Func::writeDebug("OpKey: $opkey") if DEBUG;

        if ( exists( $connhash->{$dbname}->{$opkey} ) ) {
            Foswiki::Func::writeDebug(
                "Conn Hash: " . Dumper( $connhash->{$dbname}->{$opkey} ) )
              if DEBUG;

            # First check Foswiki groups
            my @acl_keys = grep {
                     exists( $_->{allowedGroup} )
                  && Foswiki::Func::isGroup( $_->{allowedGroup} )
                  && Foswiki::Func::isGroupMember( $_->{allowedGroup}, $user )
            } @{ $connhash->{$dbname}->{$opkey} };

            Foswiki::Func::writeDebug( "Group ACL Keys: " . Dumper(@acl_keys) )
              if DEBUG;

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

            Foswiki::Func::writeDebug( "User ACL Keys: " . Dumper(@acl_keys) )
              if DEBUG;

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

=pod

sub handleError {
    my $result = shift;

    if ( eval { $result->is_error } ) {
        my $err;
        for ( $result->type ) {
            when ( 'validate' ) {
                $err = "JSON schema validation error: <br />";
                $err .= "$result->{message} <br />";
                $err =~ s/\n/\<br \/\>/;
            }
            default {
                $err = "An unspecified error occurred. <br />";
            }
        }
        return $err;
    }
}

=cut

=pod

sub idtotopic {
	my ($session, $request) = @_;

## processParams = { "id" => idfield, "pad" => padding value, "prefix" => topicprefix }
	my $jsonToProcess = $request->param('jsonQuery');
	my $processParams = $request->param('processParams');

        my $perldata = from_json($jsonToProcess);
        my $params = from_json($processParams);
        my $web = $request->param('web');
	my $idfield = $params->{id};
	my $sprintf_format = '%s%0' . $params->{pad} . 'd';
	my $ret;
        for my $sqlResult (@{ $perldata }) {
		my $id = $sqlResult->{$idfield};
		my $formattedId = sprintf($sprintf_format, $params->{prefix}, $id);
my $topicExists = Foswiki::Func::topicExists($web, $formattedId);
		if ($topicExists) {
    			push(@{$ret}, {"id" => $formattedId, "exists" => "yes"});
		} else {
    			push(@{$ret}, {"id" => $formattedId, "exists" => "no"});
		}
	}

	return encode_json($ret);
}

=cut

sub _doSelectQuery {
    my ( $jsonQuery, $dbname ) = @_;

    my ( $whitelist_rules, $err ) = _checkAcl( $dbname, 'select' );
    if ($whitelist_rules) {
        Foswiki::Func::writeDebug(
            "Whitelist Rules: " . Dumper($whitelist_rules) )
          if DEBUG;
        my ( $selectObj, $err ) =
          JsonSQL::Query::Select->new( $whitelist_rules, $jsonQuery );
        if ($selectObj) {
            my ( $sql, $binds ) = $selectObj->get_select;
            Foswiki::Func::writeDebug("SQL: $sql");
            Foswiki::Func::writeDebug( "Bind Values: " . Dumper($binds) );
            my ( $dbh, $err ) = _dbConnect( $dbname, 'select' );
            if ($dbh) {
                my $result =
                  $dbh->selectall_arrayref( $sql, { Slice => {} }, @$binds );
                $dbh->disconnect;
                Foswiki::Func::writeDebug( "Result: " . Dumper($result) );
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

        Foswiki::Func::writeDebug( Dumper(@queryParams) ) if DEBUG;
        Foswiki::Func::writeDebug($queryString)           if DEBUG;
        Foswiki::Func::writeDebug( Dumper($search) )      if DEBUG;

        my $topicSearchResult =
          Foswiki::Func::query( $queryString, undef, { web => $searchWeb } );

        while ( $topicSearchResult->hasNext ) {
            my $webtopic = $topicSearchResult->next;
            Foswiki::Func::writeDebug($webtopic) if DEBUG;
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

 #	my $perldata = JsonSQL::Validator->validate_schema($submittedJson, 'insert');
 #        print Dumper($perldata);
 #	my $insertObj = JsonSQL::Query::Insert->new($perldata);

    #	my ($sql, $binds) = $insertObj->get_all_inserts;
    #	print Dumper($sql) . "\n";
    #	print Dumper($binds) . "\n";

#	my $dbh = DBI->connect('dbi:Pg:dbname=idast;host=idastdb-1','idastwiki','idastwiki',{AutoCommit=>1,RaiseError=>1,PrintError=>0});

    #	$dbh->disconnect;
}

#sub jsondbgetandsearch {
## This method needs access controls. ##

#	my ($session, $request) = @_;

#	my $submittedJson = $request->param('jsonQuery');
#	my $searchParamString = $request->param('searchParams');
#	my $searchParams = decode_json($searchParamString);
#	return $searchParams;
## { web: "web", topicPrefix: "", useForm: "", useMeta: "", metaFields: "", returnMany: false } ##

#	my $defaultParams = { 'web' => 'Main', 'topicPrefix' => '', 'useForm' => '', 'useMeta' => '', 'metaFields' => '', 'returnMany' => 0 };
#	for my $param ( keys %{ $defaultParams } ) {
#	    if ( not defined $searchParams->{$param} ) {
#	        $searchParams->{$param} = $defaultParams->{$param};
#	    }
#	};

#	my @sharedQueryStrings;
#	if ( length $searchParams->{topicPrefix} ) {
#	    push(@sharedQueryStrings, "name ~ $searchParams->{topicPrefix}*");
#	}
#	if ( length $searchParams->{useForm} ) {
#	    push(@sharedQueryStrings, "form.name ~ *$searchParams->{useForm}");
#	}

#	my $queryResults = _doSelectQuery($submittedJson);

#    my @testResults;
#    for my $result ( @{ $queryResults } ) {
#        my @queryStrings;
#        push(@queryStrings, @sharedQueryStrings);
#        if ( length $searchParams->{useForm} ) {
#            for my $field ( @{ $searchParams->{metaFields} } ) {
#                my $string = "$searchParams->{useForm}";
#                $string .= "[name='$field'].value = '$result->{$field}'";
#                push(@queryStrings, $string);
#            }
#	    } elsif ( length $searchParams->{useMeta} ) {
#	        for my $field ( @{ $searchParams->{metaFields} } ) {
#	            my $string = "$searchParams->{useMeta}";
#               $string .= "[name='$field'].value = '$result->{$field}'";
#               push(@queryStrings, $string);
#           }
#	    }

#	    my $queryString = join(' AND ', @queryStrings);
#	    push(@testResults, $queryString);
#        my $topicSearchResult = Foswiki::Func::query( $queryString, undef, { web => $searchParams->{web} } );
#        my @foundTopics;
#        while ( $topicSearchResult->hasNext ) {
#            my $webtopic = $topicSearchResult->next;
#            my ($web, $topic) = Foswiki::Func::normalizeWebTopicName('', $webtopic);
#            push(@foundTopics, "$web.$topic");
#        }

#        if ( $searchParams->{returnMany} ) {
#            $result->{topicsFound} = \@foundTopics;
#        } else {
#          push(@testResults, { topicsFound => @foundTopics[0] || '' });
#            $result->{topicsFound} = @foundTopics[0] || '';
#        }
#    }

# my $retJson = encode_json($queryResults);
#    my $retJson = encode_json(\@testResults);

#    return $retJson;
#}

#	my $formatId = $request->param('formatId');
#    my $returnSearch = $request->param('returnSearch');

#Foswiki::Func::writeDebug($ret);
#    if ($formatId) {
#	my $formatParams = from_json($formatId);
#	my $withParams = $formatParams->{with};
## $formatParams = {"idfield": idfield, "as": resultfield, "with": {"pad": pad, "prefix": prefix}}
#	my $sprintf_format = '%s%0' . $withParams->{pad} . 'd';
#	for my $sqlResult (@{$result}) {
#		my $formattedId = sprintf($sprintf_format, $withParams->{prefix}, $sqlResult->{$formatParams->{idfield}});
#		$sqlResult->{$formatParams->{as}} = $formattedId;
#
#		if ($returnSearch) {
#			my $searchParams = from_json($returnSearch);
#			my $searchTopic = $searchParams->{topicPrefix} . $formattedId;
#			my $topicExists = Foswiki::Func::topicExists($searchParams->{web}, $searchTopic);
#			if ($topicExists) {
#				$sqlResult->{"topicExists"} = $searchTopic;
#			}
#		}
#	}
#   }

#return $sql;
## This block implements access controls. Need to adapt for JSON.
#
#    my ( $session, $params, $theTopic, $theWeb ) = @_;
#
#    my $web   = $params->{web}   || $theWeb;
#    my $topic = $params->{topic} || $theTopic;
#    ( $web, $topic ) = Foswiki::Func::normalizeWebTopicName( $web, $topic );
#    my $join = $params->{join} || 'no';
#
# check topic exists
#    unless ( Foswiki::Func::topicExists( $web, $topic ) ) {
#        return
#"<noautolink><span class='foswikiAlert'>HistoryPlugin error: Topic $web.$topic does not exist</noautolink>";
#    }
#
#    # check access permissions
#    unless (
#        Foswiki::Func::checkAccessPermission(
#            "VIEW", $session->{user}, undef, $topic, $web
#        )
#      )
#    {
#        throw Foswiki::AccessControlException( "VIEW", $session->{user}, $web,
#            $topic, $Foswiki::Meta::reason );
#    }

=pod

sub _formatId {
    my ($session, $params, $topic, $web, $topicObject) = @_;

    my $id = $params->{id} || $params->{_DEFAULT};
    my $pad = $params->{pad} || '4';
    my $prefix = $params->{prefix} || '';

    my $sprintf_format = '%s%0' . $pad . 'd';

    return sprintf($sprintf_format, $prefix, $id);
}

=cut

=pod

sub jsontest {
    my ($session, $request) = @_;
    
    my $json = '
{
    "fields": [
		{"column": "field1"},
		{"column": "field2", "alias": "test"}
	],
	"from": [
	    {"table": "table1", "schema": "MySchema"}
	], 
	"where": {
		"and": [
		    { "eq": {"field": {"column": "field2"}, "value": "Test.Field2"} },
		    { "eq": {"field": {"column": "field1"}, "value": "453.6"} },
		    { "or": [
		        { "eq": {"field": {"column": "field2"}, "value": "field3"} },
		        { "gt": {"field": {"column": "field3"}, "value": "45"} }
		    ]}
		]
	}
}';

#my $perldata = JsonSQL::Validator->validate_schema($json, 'select');

#my $select = JsonSQL::Query::Select->new($perldata);

#my ($sql, $binds) = $select->get_select;
#my $ret = $sql . "\n" . join(", ", @{ $binds }) . "\n";

#return $ret;

my $submittedJson = $request->param('jsonQuery');
my $perldata = JsonSQL::Validator->validate_schema($submittedJson, 'select');

my $selectObj = JsonSQL::Query::Select->new($perldata);

my ($sql, $binds) = $selectObj->get_select;
my $ret = $sql . "\n" . join(", ", @{ $binds }) . "\n";

#Foswiki::Func::writeDebug($ret);

return $ret;

}

=cut

1;

__END__
