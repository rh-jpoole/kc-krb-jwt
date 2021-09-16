#!/usr/bin/env python
import json,requests,re,argparse,os,boto3,gssapi
from requests_gssapi import HTTPSPNEGOAuth
from lxml import html
from getpass import getpass

def get_token(client,client_secret,redirect,base_url,auth_uri,token_uri,method,verify_ssl,user,password):
    session = requests.session()
    if method == 'kerberos':
      try:
        spnego = gssapi.mechs.Mechanism.from_sasl_name("SPNEGO")
      except AttributeError:
        spnego = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")
      kerberos_auth = HTTPSPNEGOAuth(opportunistic_auth=True,mech=spnego)
      access_code_params = {'client_id': client, 'response_type': 'code', 'scope': 'openid', 'redirect_uri': redirect}
      get_auth_response = session.get(base_url + auth_uri, params=access_code_params , verify=verify_ssl, auth=kerberos_auth, allow_redirects=False)
      matches = re.search('&code=(.*?)$', get_auth_response.headers['Location'])
      code = matches.group(1)
      token_params = {'code': code, 'grant_type': 'authorization_code', 'client_id': client, 'client_secret': client_secret, 'redirect_uri': redirect}
      token_response = session.post(base_url + token_uri, token_params, allow_redirects=False, verify=verify_ssl)
      session.close()
      return token_response.text

    if method == 'password':
      if user is None:
        user = input('username: ')
      if password is None:
        password = getpass()
      token_params = {'grant_type': 'password', 'client_id': client, 'client_secret': client_secret, 'redirect_uri': redirect, 'username': user, 'password': password, 'scope': 'openid'}
      token_response = session.post(base_url + token_uri, token_params, allow_redirects=False, verify=verify_ssl)
      session.close()
      return token_response.text


def main():
  parser = argparse.ArgumentParser(description='Obtain JWT using Kerberos or Password Auth from KeyCloak server and optionally exchange for temporary S3 credentials for RADOS gateway.')
  parser.add_argument('-c','--client', help="RH-SSO Client name", required=True)
  parser.add_argument('-s','--client-secret', help="RH-SSO Client secret", required=True)
  parser.add_argument('-e','--rgw-endpoint', help="Ceph RGW endpoint (redirect_url)", required=True)
  parser.add_argument('-b','--base-url', help="RH-SSO URL", required=True)
  parser.add_argument('-a','--auth-uri', help="RH-SSO auth endpoint (default '/auth')", default='/auth')
  parser.add_argument('-t','--token-uri', help="RH-SSO token endpoint (default '/token')", default='/token')
  parser.add_argument('-m','--method', choices=['kerberos','password'], help="Authentication method, either kerberos or password (default 'kerberos')", default='kerberos')
  parser.add_argument('-u','--user', help="Username, for use with 'password' method.")
  parser.add_argument('-p','--password', help="Password, for use with 'password' method.")
  parser.add_argument('-k','--verify-ssl', help="Verify SSL - can be either True/False/path to CA certificate (default 'True')", default=True)
  parser.add_argument('-r','--role-arn', help="Role arn to assume")
  parser.add_argument('-d','--duration', help="Seconds credentials are valid for. Default is 3600 (1h), maximum is 43200 (12h) - note this is configurable in Ceph so restrictions may differ.", default=3600)
  args = parser.parse_args()
  token = get_token(args.client,args.client_secret,args.rgw_endpoint,args.base_url,args.auth_uri,args.token_uri,args.method,args.verify_ssl,args.user,args.password)
  parsed_token = json.loads(token)
  for output in ['id_token','access_token','refresh_token']:
    print("export KC_" + output.upper() +"=" + parsed_token[output])
  if args.role_arn is not None:
    role_session_name = os.getenv('USER')
    parsed_token = json.loads(token)
    sts_client = boto3.client(
       'sts',
       aws_access_key_id="",
       aws_secret_access_key="",
       endpoint_url=args.rgw_endpoint.strip("/"),
       region_name='',
    )
    response = sts_client.assume_role_with_web_identity(
      RoleArn=args.role_arn,
      RoleSessionName=role_session_name,
      DurationSeconds=args.duration,
      WebIdentityToken=parsed_token['id_token'],
    )
    print("export AWS_ACCESS_KEY_ID=" + response['Credentials']['AccessKeyId'])
    print("export AWS_SECRET_ACCESS_KEY=" + response['Credentials']['SecretAccessKey'])
    print("export AWS_SESSION_TOKEN=" + response['Credentials']['SessionToken'])

if __name__ == "__main__":
    main()
