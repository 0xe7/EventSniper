# EventSniper

This tool is a PoC to demonstrate correlating Windows events on the server and client side as well as other sources to detect potential malicious behaviour. The tool is previewed in the blog post [The Client/Server Relationship — A Match Made In Heaven](https://trustedsec.com/blog/the-client-server-relationship-a-match-made-in-heaven) by [Andrew Schwartz](https://twitter.com/4ndr3w6S), [Jonny Johnson](https://twitter.com/jsecurity101) and myself.

It currently has 2 different command:

* `u2u` - for potentially detecting User-to-User requests
* `asreq` - for potentially detecting AS requested service tickets

The following *optional* arguments are common to both commands (although without them it will use the current security context):

* `/domain:[DOMAIN]` - the domain FQDN
* `/user:[USERNAME]` - the username to use to authenticate
* `/pass:[PASSWORD]` - the password to use to authenticate
* `/server:[DC NAME]` - the server to query (otherwise a random one is picked)

## u2u

The following optional switch can be used:

* `/ldapverify` - use LDAP to verify that the service account has no SPN (may help exclude false positives)

Examples:

Use current security context to look for U2U requests and verify using LDAP that the service account does not have an SPN set: 
```
EventSniper.exe /u2u /ldapverify
```

Use alternative credentials to look for U2U requests:
```
EventSniper.exe /u2u /domain:example.com /user:Administrator /pass:Password123
```

## asreq

The following optional switch can be used:

* `/excluderodc` - attempt to exclude any RODC krbtgt requests (may help exclude false positives)

Examples:

Use current security context to look for AS requested service tickets:
```
EventSniper.exe /asreq
```

Use alternative credentials to look for AS requested service tickets, while excluding RODC's:
```
EventSniper.exe /asreq /excluderodc /domain:example.com /user:Administrator /pass:Password123
```