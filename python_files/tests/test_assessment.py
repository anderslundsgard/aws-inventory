import pytest
from assessment.assessment import Assessment, ComplianceStatus, Check, CheckMetadata



def test__empty_assessment_has_no_checks():
    # Arrange
    assessment = Assessment('playground-dev', '123456789098')

    # Act
    # handler(event, None)

    # Assert
    assert len(assessment.checks) == 0


def test__retrieve_noncompliant_checks():
    # Arrange
    check_compliant = Check('TestService', '...', ComplianceStatus.Compliant)
    check_noncompliant = Check('IAM', 'No IAM users...', ComplianceStatus.NonCompliant)

    assessment = Assessment('playground-dev', '123456789098')
    assessment.add_check(check_compliant)
    assessment.add_check(check_noncompliant)

    # Act
    checks = assessment.non_compliant_checks()
    # handler(event, None)

    # Assert
    assert len(checks) == 1


def test__create_non_compliant_assessment():
    # Arrange
    check = Check('IAM', 'No IAM users...', ComplianceStatus.NonCompliant)
    metadata = CheckMetadata(key='ResourceId', value='i-345bh34bjky56b34')
    check.add_metadata(metadata)

    assessment = Assessment('playground-dev', '123456789098')
    assessment.add_check(check)

    assessment_readable = str(assessment)
    print(assessment_readable)
    
    # Assert
    assert 'i-345bh34bjky56b34' in assessment_readable