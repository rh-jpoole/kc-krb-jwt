#!/usr/bin/env python
import requests,urllib,re,argparse,sys
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from lxml import html
from getpass import getpass

def get_token(client,client_secret,redirect,base_url,auth_uri,token_uri,method,verify_ssl):
    session = requests.session()
    if method == 'kerberos':
      kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL, force_preemptive=True)
      access_code_params = {'client_id': client, 'response_type': 'code', 'scope': 'openid', 'redirect_uri': redirect}
      try:
        get_auth_response = session.get(base_url + auth_uri + "?" + urllib.parse.urlencode(access_code_params), verify=verify_ssl, auth=kerberos_auth, allow_redirects=False)
      except Exception as e:
        print("Something went wrong with auth")
        print(e)
        session.close()
        sys.exit(1)
      try:
        matches = re.search('&code=(.*?)$', get_auth_response.headers['Location'])
        code = matches.group(1)
        token_params = {'code': code, 'grant_type': 'authorization_code', 'client_id': client, 'client_secret': client_secret, 'redirect_uri': redirect}
        token_response = session.post(base_url + token_uri, token_params, allow_redirects=False, verify=verify_ssl)
        return token_response.text
      except Exception as e:
        print("Something went wrong obtaining the JWT")
        print(e)
        session.close()
        sys.exit(1)
      finally:
        session.close()
    if method == 'password':
      user = input('username: ')
      password = getpass()
      token_params = {'grant_type': 'password', 'client_id': client, 'client_secret': client_secret, 'redirect_uri': redirect, 'username': user, 'password': password, 'scope': 'openid'}
      try:
        jwt_response = session.post(base_url + token_uri, token_params, allow_redirects=False, verify=verify_ssl)
        return jwt_response.text
      except Exception as e:
        print("Something went wrong obtaining the JWT")
        print(e)
        session.close()
        sys.exit(1)
      finally:
        session.close()

def main():
  parser = argparse.ArgumentParser(description='Obtain JWT using Kerberos or Password Auth.')
  parser.add_argument('-c','--client', help="RH-SSO Client name", required=True)
  parser.add_argument('-s','--client-secret', help="RH-SSO Client secret", required=True)
  parser.add_argument('-e','--ceph-endpoint', help="RH Ceph endpoint (redirect_url)", required=True)
  parser.add_argument('-b','--base-url', help="RH-SSO URL", required=True)
  parser.add_argument('-a','--auth-uri', help="RH-SSO auth endpoint", default='/auth')
  parser.add_argument('-t','--token-uri', help="RH-SSO token endpoint", default='/token')
  parser.add_argument('-m','--method', choices=['kerberos','password'], help="Authentication method, either kerberos or password", default='kerberos')
  parser.add_argument('-k','--verify-ssl', help="Verify SSL - can be either True/False/path to CA certificate", default=True)
  args = parser.parse_args()
  token = get_token(args.client,args.client_secret,args.ceph_endpoint,args.base_url,args.auth_uri,args.token_uri,args.method,args.verify_ssl)
  print(token)

if __name__ == "__main__":
    main()
