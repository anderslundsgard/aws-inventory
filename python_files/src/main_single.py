import getopt, sys
from checks import scan_single_account


def print_usage():
    print('Usage:')
    print('>. .run_single_checks re-gion-1')
    print('..or multi region:')
    print('>. .run_single_checks re-gion-1,re-gion-2')

opts, args = getopt.getopt(sys.argv[1:], "ho:v", ["help", "output="])

regions = []

if len(args) == 0:
    print_usage()
    print('')
    print('No region provided. Defaults to Ireland (eu-west-1)')
    regions.append('eu-west-1')
elif len(args) == 1:
    regions = args[0].split(',')
else:
    print_usage()
    sys.exit(2)

scan_single_account(regions)
