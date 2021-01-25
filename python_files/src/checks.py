import boto3
from botocore.exceptions import ClientError
from helpers import assume_role_session
from colorama import Fore, Back, Style


region = 'eu-west-1'
audit_role_name = 'gov-audit-role'


def scan_single_account():
    print_caller_identity()

    dsp = [f for fname, f in sorted(globals().items()) if callable(f)]

    for function in dsp:
        function_name = function.__name__
        if 'inventory' in function_name:
            compliant = function()
            if not compliant:
                print(f'Failed on: {function_name}')

    
    print('')
    print('========================================================================================================')
    print('DONE!')


def scan_organization_accounts():
    print_caller_identity()

    dsp = [f for fname, f in sorted(globals().items()) if callable(f)]

    client_organizations_mfa = boto3.client('organizations')
    response = client_organizations_mfa.list_accounts()
    accounts = []

    print('')
    print('----------------------------------------------------------------------------------------------------')
    print('***** Accounts *****')
    count = 0
    for account in response['Accounts']:
        account_name = account['Name']
        account_id = account['Id']
        accounts.append(account_id)
        print(f'{count}: {account_name} ({account_id})')
        count += 1
    
    print('')
    print('----------------------------------------------------------------------------------------------------')
    print('***** Checks *****')
    format_table_pattern_header = '{:<48}'  # {:<30s}{:<20s}{:<15s}'
    format_table_pattern = '{:<50}'  # {:<30s}{:<20s}{:<15s}'
    
    count = 1
    header_checks_columns = []
    for function in dsp:
        function_name = function.__name__
        if 'inventory' in function_name:
            print(f'{count}: {function_name}')
            format_table_pattern += '{:<7s}'     
            format_table_pattern_header += '{:<7s}'     
            header_checks_columns.append(f'{count}  ') 
            count += 1               
    format_table_pattern += '{:<7s}'

    print('')
    print('----------------------------------------------------------------------------------------------------')
    header_line = format_table_pattern_header.format('Account Name', *header_checks_columns)
    print(header_line)

    # Scan all accounts
    for account in response['Accounts']:
        account_name = account['Name']
        account_id = account['Id']
        accounts.append(account_id)

        session = assume_role_session(RoleArn=f'arn:aws:iam::{account_id}:role/{audit_role_name}', SessionName='AWS-Inventory')

        checks_passed = []
        for function in dsp:
            function_name = function.__name__
            if 'inventory' in function_name:
                check_passed = function(session)                
                check_string = Back.GREEN + '   \u2665   ' if check_passed else Back.RED + '   \u2020   '
                checks_passed.append(check_string)
        lines = format_table_pattern.format(Back.BLACK + account_name, *checks_passed, Back.BLACK + '')
        print(lines)


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
def inventory_account_mfa_on_root_user(session = boto3) -> bool:
    client = session.client('iam')
    response = client.get_account_summary()
    account_mfa_enabled = response['SummaryMap']['AccountMFAEnabled']
    if not account_mfa_enabled:
        # print('$$$ MFA on ROOT is not enabled')
        return False
    return True


# EC2 - Security Groups should not be wide open for the world
def inventory_ec2_wide_open_security_groups(session = boto3) -> bool:
    client = session.client('ec2', region)
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
                        return False
                        # print(f'$$$ Incompliant security group: {group_name}')
    
    return True


# # EC2 - Number of Instances
# def inventory_ec2_instances(session = boto3):
#     client = session.client('ec2', region)
#     # print('inventory_ec2_instances')


# IAM - Number of IAM Users
def inventory_iam_users(session = boto3) -> bool:
    client = session.client('iam')
    response = client.list_users()
    users_count = len(response['Users'])
    if users_count > 0:
        # print(f'$$$ {users_count} IAM Users found!')
        return False

    return True


# IAM - Wide open IAM roles
def inventory_wide_open_iam_role(session = boto3) -> bool:
    client = session.client('iam')
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
                    # print(f'$$$ Wide open IAM Role: {role_name}')
                    return False

    return True


# SQS - Wide open SQS queue
def inventory_wide_open_sqs_queue(session = boto3) -> bool:
    client = session.client('sqs', region)
    response = client.list_queues()
    if 'QueueUrls' not in response:
        return True
        
    for queue_url in response['QueueUrls']:
        response_policy = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
        policy_json = response_policy['Attributes']['Policy']
        policy = eval(policy_json)
        for statement in policy['Statement']:
            if statement['Principal'] == '*':
                return False    
        
    return True
        