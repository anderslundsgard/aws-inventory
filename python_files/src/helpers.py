import boto3


def assume_role_session(RoleArn, SessionName, ExternalId=None):
    """
    Usage:
        session = role_arn_to_session(
            RoleArn='arn:aws:iam::012345678987:role/audit-role',
            RoleSessionName='SessionName')
        client = session.client('iam')
    """
    client = boto3.client('sts')
    
    if not ExternalId: 
        response = client.assume_role(RoleArn=RoleArn, RoleSessionName=SessionName)
    else:
        response = client.assume_role(RoleArn=RoleArn, RoleSessionName=SessionName, ExternalId=ExternalId)

    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
        region_name='eu-west-1'
    )
