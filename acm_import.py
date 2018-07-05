#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {
	'metadata_version': '1.1',
	'status': ['preview'],
	'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: acm_import

short_description: Ansible module that imports a certificate into AWS Certificate Manager (ACM) to use with services that are integrated with ACM.

version_added: "2.5"

description:
	- "Imports a certificate into AWS Certificate Manager (ACM) to use with services that are integrated with ACM. Note that integrated services allow only certificate types and keys they support to be associated with their resources. Further, their support differs depending on whether the certificate is imported into IAM or into ACM. For more information, see the documentation for each service. For more information about importing certificates into ACM, see Importing Certificates in the AWS Certificate Manager User Guide.

Note the following guidelines when importing third party certificates:

 - You must enter the private key that matches the certificate you are importing.
 - The private key must be unencrypted. You cannot import a private key that is protected by a password or a passphrase.
 - If the certificate you are importing is not self-signed, you must enter its certificate chain.
 - If a certificate chain is included, the issuer must be the subject of one of the certificates in the chain.
 - The certificate, private key, and certificate chain must be PEM-encoded.
 - The current time must be between the Not Before and Not After certificate fields.
 - The Issuer field must not be empty.
 - The OCSP authority URL, if present, must not exceed 1000 characters.
 - To import a new certificate, omit the CertificateArn argument. Include this argument only when you want to replace a previously imported certificate.
 - When you import a certificate by using the CLI, you must specify the certificate, the certificate chain, and the private key by their file names preceded by file:// . For example, you can specify a certificate saved in the C:  emp folder as file://C:  emp\certificate_to_import.pem . If you are making an HTTP or HTTPS Query request, include these arguments as BLOBs.
 - When you import a certificate by using an SDK, you must specify the certificate, the certificate chain, and the private key files in the manner required by the programming language you're using.
"

options:
    aws_access_key:
        description:
          - AWS access key. If not set then the value of the AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY or EC2_ACCESS_KEY environment variable is used.
        required: false
        default: false
        aliases: [ 'ec2_access_key', 'access_key' ]
    aws_secret_key:
        description:
          - AWS secret key. If not set then the value of the AWS_SECRET_ACCESS_KEY, AWS_SECRET_KEY, or EC2_SECRET_KEY environment variable is used.
        required: false
        default: false
        aliases: [ 'ec2_secret_key', 'secret_key' ]
    cert:
        description:
          - The path to, or content of the certificate body in PEM encoded format. As of 2.4 content is accepted. If the parameter is not a file, it is assumed to be content.
        required: false
        aliases: []
    cert_arn:
        description:
          - The Amazon Resource Name (ARN) of an imported certificate to replace. To import a new certificate, omit this option.
        required: false
        aliases: []
    cert_chain:
            description:
              - The path to, or content of the CA certificate chain in PEM encoded format. As of 2.4 content is accepted. If the parameter is not a file, it is assumed to be content.
            required: false
        aliases: []
    name:
        description:
          - Name of certificate to add.
        required: false
        aliases: []
    key:
        description:
          - The path to, or content of the private key in PEM encoded format. As of 2.4 content is accepted. If the parameter is not a file, it is assumed to be content.
        required: false
        aliases: []
    region:
        description:
          - The AWS region to use. If not specified then the value of the AWS_REGION or EC2_REGION environment variable, if any, is used. See http://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region
        required: true
        aliases: [ 'aws_region', 'ec2_region' ]
    security_token:
        description:
          - AWS STS security token. If not set then the value of the AWS_SECURITY_TOKEN or EC2_SECURITY_TOKEN environment variable is used.
        required: false
        default: None
        aliases: [ 'access_token' ]

requirements: 
  - boto
  - boto3
  - pyopenssl

extends_documentation_fragment:
	- aws

author:
	- Steven Alexson (@stevenalexson)
'''

EXAMPLES = '''
# Import a self-signed certificate from files
- name: Import self-signed cert from file
  acm_import:
    certificate: /files/certs/mycert.pem
    private_key: /files/certs/privkey.pem

# Import a self-signed certificate with data
- name: Import self-signed cert with data
  acm_import:
    certificate: '---BEGIN CERTIFICATE---<certificate_data>---END CERTIFICATE---'
    private_key: '---BEGIN RSA KEY---<key_data>---END RSA KEY---'

# Import a Public CA-signed certificate from files
- name: Import public cert from file
  acm_import:
    certificate: /files/certs/mycert.pem
    private_key: /files/certs/privatekey.pem
    certificate_chain: /files/certs/cachain.pem

# Import a Public CA-signed certificate with data
- name: Import public cert with data
  acm_import:
    certificate: '---BEGIN CERTIFICATE---<certificate_data>---END CERTIFICATE---'
    private_key: '---BEGIN RSA KEY---<key_data>---END RSA KEY---'
    certificate_chain: '---BEGIN CERTIFICATE---<certificate_chain_data>---END CERTIFICATE---'
'''

RETURN = '''
	cert_arn:
		description: The Amazon Resource Name (ARN) of the imported certificate.
'''


#####
# Import Required Libraries
#####
from ansible.module_utils.basic import *
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import (boto3_conn, get_aws_connection_info,
                                      ec2_argument_spec, camel_dict_to_snake_dict)
from OpenSSL import crypto

try:
  import boto
  import boto3
  HAS_BOTO = True
except ImportError:
  HAS_BOTO = False


#####
# Global Variable Definitions
#####
module = ''
result = {}

#####
# Function Definitions
#####


def boto_exception(error):
  if hasattr(err, 'error_message'):
      error = err.error_message
  elif hasattr(err, 'message'):
      error = err.message
  else:
      error = '%s: %s' % (Exception, err)


def cert_dupe(client, cert):
  cert_info = {}
  cert_exists = False

  cert_components = crypto.load_certificate(crypto.FILETYPE_PEM, cert).get_subject().get_components()

  for component in cert_components:
    if component[0] == 'CN':
      cert_cn = component[1]

  cert_list = client.list_certificates()

  for cert in cert_list['CertificateSummaryList']:
    cert_info = client.describe_certificate(CertificateArn=cert['CertificateArn'])

    if cert_info['Certificate']['DomainName'] == cert_cn:
      cert_info['arn'] = cert['CertificateArn']
      cert_info['exists'] = True
      break
  else:
    cert_info['arn'] = None
    cert_info['exists'] = False

  return cert_info


def cert_action(client, state, name, cert_arn, cert, key, cert_chain):
  global module
  global result
  update = False
  
  if state == 'present':
    if cert_arn is not None:
        update = True

    else:
      dupe_data = cert_dupe(client, cert)
      
      if dupe_data['exists']:
        cert_arn = dupe_data['arn']
        update = True
      

    if update:
      changed = True

      try:
        if cert_chain is not None:
          result['import_cert'] = client.import_certificate(
            CertificateArn=cert_arn,
            Certificate=cert,
            PrivateKey=key,
            CertificateChain=cert_chain
          )
        else:
          result['import_cert'] = client.import_certificate(
            CertificateArn=cert_arn,
            Certificate=cert,
            PrivateKey=key
          )
      except:
        module.fail_json(msg="Failed to update certificate")
    else:
      changed = True

      try:
        if cert_chain is not None:
            result['import_cert'] = client.import_certificate(
              Certificate=cert,
              PrivateKey=key,
              CertificateChain=cert_chain
            )

        else:
          result['import_cert'] = client.import_certificate(
            Certificate=cert,
            PrivateKey=key,
          )
      except:
        module.fail_json(msg="Failed to import certificate")

    cert_arn = result['import_cert']['CertificateArn']

    if name is not None:
      try:
        tag_response = client.add_tags_to_certificate(
          CertificateArn=cert_arn,
            Tags=[
              {
                'Key': 'Name',
                'Value': name
              },
            ]
          )
      except:
        module.fail_json(msg="Failed to set 'Name' tag of certificate")

    module.exit_json(changed=changed, name=name, cert=cert,
                       cert_chain=cert_chain, cert_arn=cert_arn)

  elif state == 'absent':

    if client.get_certificate(CertificateArn=cert_arn):
      changed = True

      try:
        result['delete_cert'] = client.delete_certificate(CertificateArn=cert_arn)
      except:
        module.fail_json(changed=False, msg="Failed to delete certificate with ARN %s" % cert_arn)

      module.exit_json(changed=changed, cert_arn=cert_arn)
    else:
      changed = False
      module.exit_json(changed=changed, msg="Certificate with ARN %s already absent" % cert_arn)

# Main Function
def main():
  global module

  # define the available arguments/parameters that a user can pass to the module
  argument_spec = dict(
    state=dict(default=None, required=True, choices=['present', 'absent']),
    name=dict(default=None, required=False),
    cert_arn=dict(default=None, required=False),
    cert=dict(default=None, required=False),
    key=dict(default=None, required=False),
    cert_chain=dict(default=None, required=False),
    aws_access_key=dict(default=None, required=False, aliases=['ec2_access_key', 'access_key']),
    aws_secret_key=dict(default=None, required=False, aliases=['ec2_secret_key', 'secret_key'], no_log=True),
    security_token=dict(default=None, required=False, aliases=['access_token']),
    region=dict(default=None, required=True, aliases=['aws_region', 'ec2_region'])
  )

  # the AnsibleModule object will be our abstraction working with Ansible
  # this include instantiation, a couple of common attr would be the
  # args/params passed to the execution, as well as if the module
  # supports check mode
  module = AnsibleModule(
    argument_spec=argument_spec,
    mutually_exclusive=[],
    supports_check_mode=False
  )

  if not HAS_BOTO:
    module.fail_json(msg="Boto is required for this module")

  region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)

  aws_access_key = module.params.get('aws_access_key')
  aws_secret_key = module.params.get('aws_secret_key')
  security_token = module.params.get('security_token')

  try:
    if region:
      acm_client = boto3.client('acm', region, **aws_connect_kwargs)
    else:
      acm_client = boto3.client('acm', **aws_connect_kwargs)
  except boto.exception.NoAuthHandlerFound as e:
    module.fail_json(msg="Cannot authorize connection = " + str(e))

  # Parse module arguments
  state = module.params.get('state')
  name = module.params.get('name')
  cert_arn = module.params.get('cert_arn')
  key = module.params.get('key')
  cert_chain = module.params.get('cert_chain')

  if state == 'present':
    cert = open(module.params.get('cert'), 'r').read().rstrip()
    key = open(module.params.get('key'), 'r').read().rstrip()
    if cert_chain is not None:
      cert_chain = open(module.params.get('cert_chain'), 'r').read().rstrip()
  else:
    key=cert=cert_chain=None
	
  # Import certificate
  changed = False
  
  try:
    cert_action(acm_client, state, name, cert_arn, cert, key, cert_chain)
  except boto.exception.BotoServerError as err:
    module.fail_json(changed=changed, msg=str(err), debug=[cert, key])

#####
# Run Main Function
#####
if __name__ == '__main__':
	main()

