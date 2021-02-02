import getopt, sys
from checks import scan_organization_accounts


def print_usage():
    print('Usage:')
    print('>. .run_org_checks audit-role re-gion-1')
    print('..or multi region:')
    print('>. .run_org_checks audit-role re-gion-1,re-gion-2')

opts, args = getopt.getopt(sys.argv[1:], "ho:v", ["help", "output="])

regions = []

if len(args) == 0:
    print_usage()
    sys.exit(2)
elif len(args) == 1:
    print_usage()
    print('')
    print('No region provided. Defaults to Ireland (eu-west-1)')
    regions.append('eu-west-1')
if len(args) == 2:
    regions = args[1].split(',')
else:
    print_usage()
    sys.exit(2)



scan_organization_accounts(audit_role_name=args[0], regions=regions)
