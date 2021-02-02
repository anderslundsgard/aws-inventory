import getopt, sys
from checks import scan_organization_accounts



opts, args = getopt.getopt(sys.argv[1:], "ho:v", ["help", "output="])

if len(args) != 2:
    print('Enter audit role as parameter. Usage: . .run_org_checks audit-role re-gion-1')
    sys.exit(2)


scan_organization_accounts(audit_role_name=args[0], regions=args[1])
