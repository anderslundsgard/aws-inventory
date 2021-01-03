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
    print('inventory_ec2_instances')


def dont_call_me():
    client = boto3.client('ec2', 'eu-west-1')
    print('dont_call_me')


scan()


print('DONE!')
