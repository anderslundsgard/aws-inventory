import enum
import datetime
from colorama import Fore, Back, Style


class ComplianceStatus(enum.Enum):
   NotValidated = 1
   Compliant = 2
   NonCompliant = 3


class CheckMetadata:

    def __init__(self, key: str, value: str, note: str = ''):
        self.key = key
        self.value = value


# One check is one scan of one rule in one account
class Check:

    def __init__(self, service: str, name: str, compliance_status):  # = ComplianceStatus.NotValidated):
        self.service = service
        self.name = name
        self.compliance_status = compliance_status
        self.metadata = []

    def add_metadata(self, metadata: CheckMetadata):
        self.metadata.append(metadata)


# One assessment is all checks on one AWS account at a moment in time
class Assessment:

    def __init__(self, account_name: str, account_id: str):
        self.assessment_time = datetime.datetime.now
        self.account_name = account_name
        self.account_id = account_id
        self.checks = []

    def add_check(self, check: Check):
        self.checks.append(check)

    def non_compliant_checks(self) -> list:
        checks = []
        for check in self.checks:
            if check.compliance_status is ComplianceStatus.NonCompliant:
                checks.append(check)

        # non_compliant_checks = [f for val, f in self.checks if f.compliance_status is ComplianceStatus.NonCompliant]
        
        return checks


    def __str__(self):
        format_line_pattern = '{:<10}{:<100}'
        non_compliant_checks = self.non_compliant_checks()
        if len(non_compliant_checks) == 0:
            return format_line_pattern.format('Account:', f'{Fore.GREEN}{self.account_name} ({self.account_id}) - COMPLIANT{Fore.WHITE}')

        summary = format_line_pattern.format('Account:', f'{Fore.RED}{self.account_name} ({self.account_id}) - NON COMPLIANT{Fore.WHITE}')
        summary += '\n'
        
        # format_table_pattern = '{:<10}{:<50}{:<50}{:<50}{:<50}'
        for check in self.non_compliant_checks():
            check_line = format_line_pattern.format('', f'[{check.service}] {check.name}')
            summary += check_line
            summary += '\n'
            for entry in check.metadata:
                metadata_line = format_line_pattern.format('', f'     - {entry.key}: {entry.value}')
                summary += metadata_line
                summary += '\n'

        return summary
            

# Account: playground-dev (123456789098) - NON COMPLIANT
#          CloudTrail - At least one active CloudTrail trail should be present in account
#          IAM - Avoid usage of IAM Users
#           - User name: test_user
#           - User name: another user 
#
#
#