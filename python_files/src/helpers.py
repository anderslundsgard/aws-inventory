import boto3


def assume_read_only_session(RoleArn, SessionName, ExternalId=None):
    """
    Usage:
        session = assume_read_only_session(
            RoleArn='arn:aws:iam::012345678987:role/audit-role',
            RoleSessionName='SessionName')
        client = session.client('iam')
    """
    client = boto3.client('sts')
    
    if not ExternalId: 
        response = client.assume_role(RoleArn=RoleArn, PolicyArns=[{'arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}], RoleSessionName=SessionName)
    else:
        response = client.assume_role(RoleArn=RoleArn, PolicyArns=[{'arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}], RoleSessionName=SessionName, ExternalId=ExternalId)

    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
        region_name='eu-west-1'
    )


def yes_or_no(question):
    reply = str(input(question + ' (Y/n): ')).lower().strip()
    if reply == 'n':
        return False
    else:
        return True