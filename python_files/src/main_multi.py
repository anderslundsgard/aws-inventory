import getopt, sys
from checks import scan_organization_accounts



opts, args = getopt.getopt(sys.argv[1:], "ho:v", ["help", "output="])

if len(args) != 1:
    print('Enter audit role as parameter. Usage: . .run_org_checks audit-role')
    sys.exit(2)


scan_organization_accounts(audit_role_name=args[0])
