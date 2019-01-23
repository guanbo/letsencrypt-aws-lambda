import boto3
import certbot.main
import datetime
import os
import time
# import raven
import subprocess
import re

def read_and_delete_file(path):
  with open(path, 'r') as file:
    contents = file.read()
  os.remove(path)
  return contents

def get_cert_by_domain(first_domain):
  path = '/tmp/config-dir/live/' + first_domain + '/'
  return {
    'name': cert_name,
    'certificate': read_and_delete_file(path + 'cert.pem'),
    'private_key': read_and_delete_file(path + 'privkey.pem'),
    'certificate_chain': read_and_delete_file(path + 'chain.pem')
  }

def provision_cert(email, domains):
  first_domain = '.'.join(domains.split(',')[0].split('.')[-2:])
  expiration_date = datetime.datetime.now() + datetime.timedelta(days=90)
  cert_name = first_domain + '.' + expiration_date.strftime('%Y%m%d')

  certbot.main.main([
    'certonly',                             # Obtain a cert but don't install it
    '-n',                                   # Run in non-interactive mode
    '--agree-tos',                          # Agree to the terms of service,
    '--email', email,                       # Email
    '--preferred-challenges',  "dns",       # Use dns challenge with dns-01
    '-d', domains,                          # Domains to provision certs for
    '--cert-name', first_domain,
    '--manual',
    '--manual-auth-hook', 'python manual-hook.py --auth',
    '--manual-cleanup-hook', 'python manual-hook.py --cleanup',
    '--manual-public-ip-logging-ok',
    # Override directory paths so script doesn't have to be run as root
    '--config-dir', '/tmp/config-dir/',
    '--work-dir', '/tmp/work-dir/',
    '--logs-dir', '/tmp/logs-dir/',
  ])
  return get_cert_by_domain(first_domain)

def should_provision(domains, days=30):
  existing_cert = find_existing_cert(domains)
  if existing_cert:
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = existing_cert['Expiration']
    return (not_after - now).days <= days
  else:
    return True

def find_existing_cert(domains):
  certificates = find_certs()
  certs = []
  for cert in certificates:
    domain = '.'.join(cert['ServerCertificateName'].split('.')[-3:-1])
    re_domain = re.escape(domain) + r'$'
    if re.search(re_domain, domains, re.IGNORECASE):
      certs.append(cert)

  return max(certs, key=lambda c: c['Expiration']) if certs else None

def find_certs():
  client = boto3.client('iam')
  response = client.list_server_certificates()
  return response['ServerCertificateMetadataList']

# def notify_via_sns(topic_arn, domains, certificate):
#   process = subprocess.Popen(['openssl', 'x509', '-noout', '-text'],
#     stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf8')
#   stdout, stderr = process.communicate(certificate)

#   client = boto3.client('sns')
#   client.publish(TopicArn=topic_arn,
#     Subject='Issued new LetsEncrypt certificate',
#     Message='Issued new certificates for domains: ' + domains + '\n\n' + stdout,
#   )

def upload_cert_to_iam(cert):
  client = boto3.client('iam')
  iam_response = client.upload_server_certificate(
    ServerCertificateName=cert['name'],
    CertificateBody=cert['certificate'],
    PrivateKey=cert['private_key'],
    CertificateChain=cert['certificate_chain']
  )
  return iam_response

def add_cert_to_alb(listener_arn, cert_arn):
  region_name = listener_arn.split(':')[3]
  client = boto3.client('elbv2', region_name=region_name)
  response = client.add_listener_certificates(
    ListenerArn=listener_arn,
    Certificates=[
      {
        'CertificateArn': cert_arn,
      }
    ]
  )
  return response

def cleanup_certs(listener_arn, days=0):
  days = days % 30
  iam_client = boto3.client('iam')
  region_name = listener_arn.split(':')[3]
  elb_client = boto3.client('elbv2', region_name=region_name)
  certs = find_certs()
  now = datetime.datetime.now(datetime.timezone.utc)
  for cert in certs:
    if (cert['Expiration'] - now).days < days :
      elb_client.remove_listener_certificates(
        ListenerArn=listener_arn,
        Certificates=[
          {
            'CertificateArn': cert['Arn'],
          }
        ]
      )
      try:
        iam_client.delete_server_certificate(
          ServerCertificateName=cert['ServerCertificateName']
        )
      except Exception as err:
        print(err)
        pass

def get_parameter(key):
  client = boto3.client('ssm')
  resp = client.get_parameter(Name=key,WithDecryption=True)
  return resp['Parameter']['Value']

def main(event, context):
  try:
    elb_listener_arn = get_parameter('elb_listener_arn')
    letsencrypt_email = get_parameter('letsencrypt_email')
    domains_list = get_parameter('letsencrypt_domains').split('|')
    for domains in domains_list:
      if should_provision(domains, 30):
        print ('====domains:', domains)
        cert = provision_cert(letsencrypt_email, domains)
        iam_response = upload_cert_to_iam(cert)
        cert_arn = iam_response['ServerCertificateMetadata']['Arn']
        add_cert_to_alb(elb_listener_arn, cert_arn)
        # notify_via_sns(os.environ['NOTIFICATION_SNS_ARN'], domains, cert['certificate'])
    
    cleanup_certs(elb_listener_arn)
  except:
    # client = raven.Client(os.environ['SENTRY_DSN'], transport=raven.transport.http.HTTPTransport)
    # client.captureException()
    raise

if __name__ == "__main__" :
  main("", "")