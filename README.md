# Get a JWT

Script to obtain JWT token using Kerberos or username+password to authenticate against KeyCloak. If password method specified and the additional options aren't defined you will be prompted for username and password.

```
usage: getcreds.py [-h] -c CLIENT -s CLIENT_SECRET -e RGW_ENDPOINT -b BASE_URL [-a AUTH_URI] [-t TOKEN_URI] [-o {id_token,access_token,refresh_token,all}] [-m {kerberos,password}] [-u USER] [-p PASSWORD] [-k VERIFY_SSL] [-r ROLE_ARN]
                   [-d DURATION]

Obtain JWT using Kerberos or Password Auth from KeyCloak server and optionally exchange for temporary S3 credentials for RADOS gateway.

optional arguments:
  -h, --help            show this help message and exit
  -c CLIENT, --client CLIENT
                        RH-SSO Client name
  -s CLIENT_SECRET, --client-secret CLIENT_SECRET
                        RH-SSO Client secret
  -e RGW_ENDPOINT, --rgw-endpoint RGW_ENDPOINT
                        Ceph RGW endpoint (redirect_url)
  -b BASE_URL, --base-url BASE_URL
                        RH-SSO URL
  -a AUTH_URI, --auth-uri AUTH_URI
                        RH-SSO auth endpoint (default '/auth')
  -t TOKEN_URI, --token-uri TOKEN_URI
                        RH-SSO token endpoint (default '/token')
  -o {id_token,access_token,refresh_token,all}, --output {id_token,access_token,refresh_token,all}
                        Specify which token to output from id_token, access_token, refresh_token or all. Default is id_token.
  -m {kerberos,password}, --method {kerberos,password}
                        Authentication method, either kerberos or password (default 'kerberos')
  -u USER, --user USER  Username, for use with 'password' method.
  -p PASSWORD, --password PASSWORD
                        Password, for use with 'password' method.
  -k VERIFY_SSL, --verify-ssl VERIFY_SSL
                        Verify SSL - can be either True/False/path to CA certificate (default 'True')
  -r ROLE_ARN, --role-arn ROLE_ARN
                        Role arn to assume
  -d DURATION, --duration DURATION
                        Seconds creds are valid for. Default is 3600 (1h), maximum is 43200 (12h) - note this is configurable in Ceph so restrictions may differ.
```

Example:

```
getcreds/getcreds.py -c "Ceph-wdc" -s "3642f516-35a9-4980-897a-622f26986515" -e "http://192.0.0.1/" -b "http://idm.tlab.htz:8081/auth/realms/test-wdc/protocol/openid-connect" -u bob -p password -m password
```

This script can also be built into a precompiled file for distribution using the supplied Dockerfile by simply running `./build.sh`. Note this uses podman instead of docker command. The output will be located in ./getcreds/dist/.
