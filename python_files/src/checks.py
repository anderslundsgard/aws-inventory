import boto3
from botocore.exceptions import ClientError


region = 'eu-west-1'


def scan():
    print_caller_identity()

    dsp = [f for fname, f in sorted(globals().items()) if callable(f)]

    for function in dsp:
        if 'inventory' in str(function):
            function()
    
    print('')
    print('========================================================================================================')
    print('DONE!')
            

def print_caller_identity():
    try:
        client = boto3.client('sts')
        response = client.get_caller_identity()
        arn = response['Arn']
        print('')
        print('========================================================================================================')
        print(f'Caller identity: {arn}')
        print('========================================================================================================')
        print('')
    except ClientError:
        print('========================================================================================================')
        print(f'Unknown Caller identity. No access to do sts:GetCallerIdentity.')
        print(f'Make sure your current IAM User/Role has access to policies SecurityAudit and ReadOnlyAccess.')
        print('========================================================================================================')
        


# Account - MFA should be enabled on root user
def inventory_account_mfa_on_root_user():
    client = boto3.client('iam')
    response = client.get_account_summary()
    account_mfa_enabled = response['SummaryMap']['AccountMFAEnabled']
    if not account_mfa_enabled:
        print('$$$ MFA on ROOT is not enabled')


# EC2 - Security Groups should not be wide open for the world
def inventory_ec2_wide_open_security_groups():
    client = boto3.client('ec2', region)
    response = client.describe_security_groups()
    for security_group in response['SecurityGroups']:
        group_name = security_group['GroupName']
        for ip_permission in security_group['IpPermissions']:
            ip_ranges = ip_permission['IpRanges']
            for ip_range in ip_ranges:
                cidr_ip = ip_range['CidrIp']
                if cidr_ip == '0.0.0.0/0':
                    from_port = ip_permission['FromPort']
                    to_port = ip_permission['ToPort']
                    if from_port != 443 or to_port != 443:
                        print(f'$$$ Incompliant security group: {group_name}')


# EC2 - Number of Instances
def inventory_ec2_instances():
    client = boto3.client('ec2', region)
    # print('inventory_ec2_instances')


# IAM - Number of IAM Users
def inventory_iam_users():
    client = boto3.client('iam')
    response = client.list_users()
    users_count = len(response['Users'])
    if users_count > 0:
        print(f'$$$ {users_count} IAM Users found!')


# IAM - Wide open IAM roles
def inventory_wide_open_iam_role():
    client = boto3.client('iam')
    response = client.list_roles()
    roles = response['Roles']
    for role in roles:
        assume_role_policy_document = role['AssumeRolePolicyDocument']
        role_name = role['RoleName']
        statements = assume_role_policy_document['Statement']
        for statement in statements:
            principal = statement['Principal']
            if 'AWS' in principal:
                if principal['AWS'] == '*':
                    print(f'$$$ Wide open IAM Role: {role_name}')
        