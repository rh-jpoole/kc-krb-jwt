# Get a JWT

Script to obtain JWT token using Kerberos or username+password to authenticate against KeyCloak. If password method specified you will be prompted for username and password.

```
usage: getjwt.py [-h] -c CLIENT -s CLIENT_SECRET -e CEPH_ENDPOINT -b BASE_URL [-a AUTH_URI] [-t TOKEN_URI] [-m {kerberos,password}] [-k VERIFY_SSL]

Obtain JWT using Kerberos or Password Auth.

optional arguments:
  -h, --help            show this help message and exit
  -c CLIENT, --client CLIENT
                        RH-SSO Client name
  -s CLIENT_SECRET, --client-secret CLIENT_SECRET
                        RH-SSO Client secret
  -e CEPH_ENDPOINT, --ceph-endpoint CEPH_ENDPOINT
                        RH Ceph endpoint (redirect_url)
  -b BASE_URL, --base-url BASE_URL
                        RH-SSO URL
  -a AUTH_URI, --auth-uri AUTH_URI
                        RH-SSO auth endpoint
  -t TOKEN_URI, --token-uri TOKEN_URI
                        RH-SSO token endpoint
  -m {kerberos,password}, --method {kerberos,password}
                        Authentication method, either kerberos or password
  -k VERIFY_SSL, --verify-ssl VERIFY_SSL
                        Verify SSL - can be either True/False/path to CA certificate
```
