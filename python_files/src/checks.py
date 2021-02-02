import boto3
import datetime
from botocore.exceptions import ClientError
from helpers import assume_role_session
from colorama import Fore, Back, Style
from assessment.assessment import Assessment, Check, CheckMetadata, ComplianceStatus


def scan_single_account():
    regions = 'eu-west-1'
    account_id = print_caller_identity()

    dsp = [f for fname, f in sorted(globals().items()) if callable(f)]

    assessment = Assessment('Current account', account_id)

    for function in dsp:
        function_name = function.__name__
        if 'inventory' in function_name:
            check = function(regions)
            if not check or check.compliance_status is ComplianceStatus.Compliant:
                continue
            assessment.add_check(check)
            if check.compliance_status is ComplianceStatus.NonCompliant:
                print(f' *** Failed on: {function_name}')

    
    print('')
    print('========================================================================================================')
    print(str(assessment))

    print('')
    print('========================================================================================================')
    print('DONE!')


def scan_organization_accounts(audit_role_name, regions):
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

        try:
            session = assume_role_session(RoleArn=f'arn:aws:iam::{account_id}:role/{audit_role_name}', SessionName='AWS-Inventory')
        except ClientError:
            print(f'{Fore.YELLOW}{account_name}{Fore.WHITE} ({audit_role_name} not assumable)')
            continue

        checks_passed = []
        for function in dsp:
            function_name = function.__name__
            if 'inventory' in function_name:
                check = function(regions, session)                
                check_string = Back.GREEN + '   \u2665   ' if check.compliance_status is not ComplianceStatus.NonCompliant else Back.RED + '   \u2020   '
                checks_passed.append(check_string)
        lines = format_table_pattern.format(Back.BLACK + account_name, *checks_passed, Back.BLACK + '')
        print(lines)


def print_caller_identity():
    try:
        client = boto3.client('sts')
        response = client.get_caller_identity()
        arn = response['Arn']
        account_id = response['Account']
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
        return ''
        
    return account_id


def inventory_account_mfa_on_root_user(regions, session = boto3) -> Check:
    check = Check('Account', 'MFA should be enabled on root user', ComplianceStatus.Compliant)

    client = session.client('iam')
    response = client.get_account_summary()
    account_mfa_enabled = response['SummaryMap']['AccountMFAEnabled']
    if not account_mfa_enabled:
        # print('$$$ MFA on ROOT is not enabled')
        check.compliance_status = ComplianceStatus.NonCompliant
    
    return check
    

def inventory_cloudtrail_active(regions, session = boto3) -> Check:
    check = Check('CloudTrail', 'At least one active CloudTrail trail should be present in account', ComplianceStatus.Compliant)

    client = session.client('cloudtrail', regions)
    response = client.list_trails()
    trails = response['Trails']
    for trail in trails:
        trail_arn = trail['TrailARN']
        response = client.get_trail_status(Name=trail_arn)
        is_logging = response['IsLogging']
        if is_logging:
            return check

    check.compliance_status = ComplianceStatus.NonCompliant
    return check


def inventory_ec2_wide_open_security_groups(regions, session = boto3) -> Check:
    check = Check('EC2', 'Security Groups should not be wide open for the world', ComplianceStatus.Compliant)

    client = session.client('ec2', regions)
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
                        check_metadata_1 = CheckMetadata('Security group', f'{group_name}')
                        check_metadata_2 = CheckMetadata('Port ranges', f'From port: {from_port}  To port: {to_port}')
                        check.add_metadata(check_metadata_1)
                        check.add_metadata(check_metadata_2)
                        check.compliance_status = ComplianceStatus.NonCompliant
    
    return check


def inventory_iam_users(regions, session = boto3) -> Check:
    check = Check('IAM', 'IAM User with old access keys (over 90 days)', ComplianceStatus.Compliant)

    client = session.client('iam')
    response = client.list_users()
    users = response['Users']
    for user in users:
        user_name = user['UserName']
        response = client.list_access_keys(UserName=user_name)
        for key in response['AccessKeyMetadata']:
            created = key['CreateDate']
            access_key_id = key['AccessKeyId']
            age = datetime.datetime.now(datetime.timezone.utc) - created
            if age.days > 90:
                check_metadata_1 = CheckMetadata('User name', f'{user_name} (Key Id: {access_key_id}, Key days of age: {age.days})')                
                check.add_metadata(check_metadata_1)
                check.compliance_status = ComplianceStatus.NonCompliant
        
    return check


def inventory_wide_open_iam_role(regions, session = boto3) -> Check:
    check = Check('IAM', 'IAM Role wide open for the world', ComplianceStatus.Compliant)

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
                    metadata = CheckMetadata('Role', f'{role_name}')                
                    check.add_metadata(metadata)
                    check.compliance_status = ComplianceStatus.NonCompliant

    return check


def inventory_wide_open_sqs_queue(regions, session = boto3) -> Check:
    check = Check('SQS', 'SQS queue wide open for the world', ComplianceStatus.Compliant)

    client = session.client('sqs', regions)
    response = client.list_queues()
    if 'QueueUrls' not in response:
        return check
        
    for queue_url in response['QueueUrls']:
        response_policy = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
        
        policy_json = response_policy['Attributes']['Policy']
        policy = eval(policy_json)
        for statement in policy['Statement']:
            if statement['Principal'] == '*':
                metadata = CheckMetadata('SQS queue', f'{queue_url}')
                check.add_metadata(metadata)
                check.compliance_status = ComplianceStatus.NonCompliant

    return check
        

def inventory_wide_open_sns_topics(regions, session = boto3) -> Check:
    check = Check('SNS', 'SNS topic wide open for the world', ComplianceStatus.Compliant)

    client = session.client('sns', regions)
    response = client.list_topics()  # NextToken='string')
    topics = response['Topics']
    
    for topic in topics:
        topic_arn = topic['TopicArn']
        response = client.get_topic_attributes(TopicArn=topic_arn)
        attributes = response['Attributes']
        policy_json = attributes['Policy']
        policy = eval(policy_json)
        for statement in policy['Statement']:
            if statement['Principal'] == '*':
                metadata = CheckMetadata('SNS topic', f'{topic_arn}')
                check.add_metadata(metadata)
                check.compliance_status = ComplianceStatus.NonCompliant

    return check


def inventory_wide_open_s3_buckets(regions, session = boto3) -> Check:
    check = Check('S3', 'S3 bucket wide open for the world', ComplianceStatus.Compliant)

    client = session.client('s3')
    response = client.list_buckets()
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        try:
            response = client.get_bucket_policy_status(Bucket=bucket_name)
        except ClientError as e:
            # No bucket policy exist
            continue

        policy_status = response['PolicyStatus']
        if policy_status['IsPublic']:
            response = client.get_bucket_policy(Bucket=bucket_name)
            policy_json = response['Policy']
            policy = eval(policy_json)
            for statement in policy['Statement']:
                if 'Condition' not in statement:
                    metadata = CheckMetadata('Bucket name', f'{bucket_name}')
                    check.add_metadata(metadata)
                    check.compliance_status = ComplianceStatus.NonCompliant
                    break
                
    return check


# def inventory_follow_rds_best_practices(session = boto3) -> Check:
#     check = Check('RDS', 'Follow RDS best practices', ComplianceStatus.Compliant)

#     client = session.client('rds', region)
