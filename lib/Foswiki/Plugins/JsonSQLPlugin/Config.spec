# ---+ Extensions
# ---++ JsonSQLPlugin
# **PERL 20x40 LABEL='Define database connections and access rules'**
# <h2>Database access configuration table</h2>
# Here you will define a DB 'namespace' for each database you want to
# allow access to. The structure is a hash where each key of the hash
# is the namespace you are defining. The namespace itself is a hash
# reference with the following properties:
# <ul>
#   <li> <code>dsn</code> - DBI Data Source Name (DSN)</li>
#   <li> <code>allowSelect</code> - Groups or users allowed to perform SELECT operations</li>
#   <li> <code>allowInsert</code> - Groups or users allowed to perform INSERT operations</li>
# </ul>
#
# The 'dsn' property must conform to the format expected by the Perl DBI module. See
# http://search.cpan.org/~timb/DBI-1.636/DBI.pm for more info.
#
# Each of the allow[Select,Insert] properties point to an array reference of users
# and/or groups that are allowed to perform the indicated operation on the database. If more than
# one rule can apply to the current user, the following heuristic is applied:
# <ul>
#   <li> For users who are members of more than one group, group rules that come later in the allow* 
#        list override any rules that come earlier. </li>
#   <li> If a user is subject to both group rules (ie: is a member of a group) and has a specific
#        set of rules defined for that user, the user rules will override any group rules. </li>
# </ul>
#
# Finally, the 'whitelist_rules' property that accompanies each group or user rule takes the format
# defined by the JsonSQL::Validator CPAN module. See http://search.cpan.org/~hoeflerb/JsonSQL-0.4/lib/JsonSQL/Validator.pm#Whitelisting_Module
# for more info.
#
# The full structure looks like this:
# <verbatim>
#    {
#        'dbname' => {
#            dsn => 'dsn',
#            allowSelect => [
#                {
#                    allowedGroup => 'WikiGroup' || allowedUser => 'WikiUser',
#                    whitelist_rules => [
#                        {
#                            schema => 'schema',
#                            'allowedTable' => ['allowedColumns'],
#                            'allowedTable' => ['allowedColumns']
#                        }
#                    ]
#                }
#            ]
#            allowInsert => <...>
#        }
#    }
# </verbatim>
$Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbconnections} = {
    company_inventory => {
        dsn => 'dbi:Pg:dbname=inventory;host=inventory.company.com',
        allowSelect => [
            {
                allowedGroup => 'Customers',
                whitelist_rules => [
                    {
                        schema => 'product_schema',
                        'saleItems' => ['productId', 'productName', 'productPrice']
                    }
                ]
            },
            {
                allowedGroup => 'Salesforce',
                whitelist_rules => [
                    {
                        schema => 'product_schema',
                        '#anyTable' => ''
                    }
                ]
            }
        ],
        allowInsert => [
            {
                allowedGroup => 'ProductDevelopment',
                whitelist_rules => [
                    {
                        schema => 'product_schema',
                        'newItems' => ['#anyColumn']
                    }
                ]
            },
            {
                allowedUser => 'DBAdmin',
                whitelist_rules => [
                    {
                        schema => 'product_schema',
                        '#anyTable' => ''
                    }
                ]
            }
        ]
    }
};

# **PERL 20x40 LABEL='Define user mappings for database connections'**
# <h2>Database user map configuration table</h2>
# Here you will define Foswiki user to DB user mappings for each database 
# you want to allow access to, and you can specify different user mappings
# for different database operations (ex: 'insert' or 'select'). This enables
# flexible support for basic DB authentication. Advanced schemes like Kerberos 
# are not yet supported, but planned for the future. The structure of the user
# map is an array, where each array element is a hash reference containing a 
# mapping of a Foswiki user or group to allowed DB namespaces (defined above) and 
# their associated user credentials for different database operations. The keys
# of each user map hash are as follows:
# <ul>
#   <li> <code>allowedGroup</code> - a Foswiki group</li>
#   <li> <code>allowedUser</code> - a Foswiki user (wikiname)</li>
#   <li> <code>'dbname'</code> - user mappings (hashref)</li>
# </ul>
#
# The hash reference starts with a definition of either allowedGroup or allowedUser,
# and then each remaining key of the hashref is a DB namespace defined above in the
# dbconnections setting. Each DB namespace key points to a hash reference with the
# following properties:
# <ul>
#   <li> <code>default</code> - user/pass to use as a default for DB operations</li>
#   <li> <code>select</code> - user/pass to use for SELECT DB operations</li>
#   <li> <code>insert</code> - user/pass to use for INSERT DB operations</li>
# </ul>
#
# The user/pass is a third hash reference, so the full structure looks like this:
# <verbatim>
#    {
#        allowedGroup => 'WikiGroup' || allowedUser => 'WikiUser',
#        'dbname' => {
#            default => {
#                user => 'user',
#                pass => 'pass'
#            },
#            select => {
#                user => 'user',
#                pass => 'pass'
#            },
#            insert => {
#                user => 'user',
#                pass => 'pass'
#            }
#        }
#    }
# </verbatim>
#
# The 'default' user mapping is only used if either 'select' or 'insert' is not defined. As
# with the DB namespace definitions, the following heuristic applies if more than one
# mapping can apply to the current user:
# <ul>
#   <li> For users who are members of more than one group, group mappings for a DB that come later 
#        in the list override any mappings that come earlier. </li>
#   <li> If a user is subject to both group mappings (ie: is a member of a group) and has a specific
#        user mapping, the user mapping will override any group mappings. </li>
# </ul>
$Foswiki::cfg{Extensions}{JsonSQLPlugin}{dbusermap} = [
    {
        allowedGroup => 'Customers',
        'company_inventory' => {
            select => {
                user => 'wikicustomer',
                pass => 'wIKiCu$tomer%'
            }
        }
    },
    {
        allowedGroup => 'Salesforce',
        'company_inventory' => {
            select => {
                user => 'salesrep',
                pass => '$Ales-ReP)'
            }
        }
    },
    {
        allowedGroup => 'ProductDevelopment',
        'company_inventory' => {
            insert => {
                user => 'pd_agent',
                pass => 'secretpass'
            }
        }
    },
    {
        allowedUser => 'DBAdmin',
        'company_inventory' => {
            default => {
                user => 'dbadmin',
                pass => 'verysecretpass'
            }
        }
    }
];

1;
