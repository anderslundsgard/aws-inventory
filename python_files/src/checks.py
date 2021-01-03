import boto3


def scan():
    print_caller_identity()

    dsp = [f for fname, f in sorted(globals().items()) if callable(f)]

    for function in dsp:
        if 'inventory' in str(function):
            function()
            

def print_caller_identity():
    client = boto3.client('sts')
    response = client.get_caller_identity()
    arn = response['Arn']
    print('========================================================================================================')
    print(f'Caller identity: {arn}')
    print('========================================================================================================')


# EC2 - Number of Instances
def inventory_ec2_instances():
    client = boto3.client('ec2', 'eu-west-1')
    # print('inventory_ec2_instances')


# IAM - Number of IAM Users
def inventory_iam_users():
    client = boto3.client('iam')
    response = client.list_users()
    users_count = len(response['Users'])
    if users_count > 0:
        print(f'$$$ {users_count} IAM Users found!')


scan()

print('')
print('========================================================================================================')
print('DONE!')
