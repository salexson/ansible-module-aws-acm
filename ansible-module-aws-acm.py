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
 - When you import a certificate by using the CLI, you must specify the certificate, the certificate chain, and the private key by their file names preceded by file:// . For example, you can specify a certificate saved in the C:\temp folder as file://C:\temp\certificate_to_import.pem . If you are making an HTTP or HTTPS Query request, include these arguments as BLOBs.
 - When you import a certificate by using an SDK, you must specify the certificate, the certificate chain, and the private key files in the manner required by the programming language you're using.
"

options:
	aws_access_key:
		description: AWS access key. If not set then the value of the AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY or EC2_ACCESS_KEY environment variable is used.
		required: false
		default: None
		aliases: access_key
	aws_secret_key:
		description: AWS secret key. If not set then the value of the AWS_SECRET_ACCESS_KEY, AWS_SECRET_KEY, or EC2_SECRET_KEY environment variable is used.
		required: false
		default: None
		aliases: secret_key
	cert:
		description: The path to, or content of the certificate body in PEM encoded format. As of 2.4 content is accepted. If the parameter is not a file, it is assumed to be content.
		required: true
	cert_arn:
		description: The Amazon Resource Name (ARN) of an imported certificate to replace. To import a new certificate, omit this option.
		required: false
	certificate_chain:
		description: The path to, or content of the CA certificate chain in PEM encoded format. As of 2.4 content is accepted. If the parameter is not a file, it is assumed to be content.
		required: false
	name:
		description: Name of certificate to add.
		required: false
	private_key:
		description: The path to, or content of the private key in PEM encoded format. As of 2.4 content is accepted. If the parameter is not a file, it is assumed to be content.
		required: true
	security_token:
		description: AWS STS security token. If not set then the value of the AWS_SECURITY_TOKEN or EC2_SECURITY_TOKEN environment variable is used.
		required: false
		default: None
		aliases: access_token

extends_documentation_fragment:
	- aws

author:
	- Steven Alexson (@stevenalexson)
'''

EXAMPLES: '''
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
	certificate_arn:
		description: The Amazon Resource Name (ARN) of the imported certificate.
'''

#####
# Import Required Libraries
#####
from ansible.module_utils.basic import AnsibleModule
import boto3


#####
# Function Definitions
#####

## Main Function
def main():
	# define the available arguments/parameters that a user can pass to the module
	module_args = dict(
		aws_access_key=dict(type str, required=False),
		aws_secret_key=dict(type str, required=False),
		aws_session_token=dict(type str, required=False,
		cert_arn=dict(type=str, required=False),
		cert=dict(type=str, required=True),
		key=dict(type=str, required=True),
		cert_chain(type=str, required=False)
	)

	# seed the result dict in the object
	# change is if the module effectively modified the target
	# state will include any data that the module should pass back
	# for consumption
	result = dict(
		changed=False,
		certificate_arn=''
	)

	# the AnsibleModule object will be our abstraction working with Ansible
	# this include instantiation, a couple of common attr would be the
	# args/params passed to the execution, as well as if the module
	# supports check mode
	module = AnsibleModule(
		argument_spec=module_args,
		supports_check_mode=False
	)

	# Establish Boto3 Client
	if (aws_access_key_id == ''):
		acm = boto3.client('acm')
	else:
		acm = boto3.client('acm', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token
	
	# Import certificate
	if certificate_arn != '':
		result['import_cert'] = acm.import_certificate(
			CertificateArn=certficiate_arn,
			Certificate=certificate,
			PrivateKey=private_key,
			CertificateChain=certificate_chain
		)


#####
# Run Main Function
#####
if __name__ == '__main__':
	main()
