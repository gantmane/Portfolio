#!/usr/bin/env python3
"""
IAM Policy Validator
Author: Evgeniy Gantman
Purpose: Validate IAM policies for syntax, security best practices, and compliance
PCI DSS: Supports validation of PCI DSS access control requirements
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

class IAMPolicyValidator:
    """Validate IAM policies for security and compliance"""

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []

    def validate_policy_file(self, policy_file: str) -> Tuple[bool, List[str], List[str]]:
        """
        Validate a single IAM policy file

        Args:
            policy_file: Path to IAM policy JSON file

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        logger.info(f"Validating policy: {policy_file}")

        # Reset validation results
        self.errors = []
        self.warnings = []
        self.info = []

        # Load policy
        try:
            with open(policy_file, 'r') as f:
                policy = json.load(f)
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON: {str(e)}")
            return False, self.errors, self.warnings
        except FileNotFoundError:
            self.errors.append(f"File not found: {policy_file}")
            return False, self.errors, self.warnings

        # Validate structure
        self._validate_structure(policy)

        # Validate security best practices
        self._validate_security_best_practices(policy)

        # Validate PCI DSS requirements
        self._validate_pci_dss(policy)

        # Check for overly permissive policies
        self._check_permissions(policy)

        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings

    def _validate_structure(self, policy: Dict):
        """Validate basic IAM policy structure"""
        # Check Version
        if 'Version' not in policy:
            self.errors.append("Missing 'Version' field")
        elif policy['Version'] != '2012-10-17':
            self.warnings.append(f"Unexpected version: {policy['Version']}")

        # Check Statement
        if 'Statement' not in policy:
            self.errors.append("Missing 'Statement' field")
            return

        if not isinstance(policy['Statement'], list):
            self.errors.append("'Statement' must be a list")
            return

        if len(policy['Statement']) == 0:
            self.warnings.append("Policy has no statements")

        # Validate each statement
        for idx, statement in enumerate(policy['Statement']):
            self._validate_statement(statement, idx)

    def _validate_statement(self, statement: Dict, idx: int):
        """Validate individual policy statement"""
        # Check required fields
        if 'Effect' not in statement:
            self.errors.append(f"Statement {idx}: Missing 'Effect'")
        elif statement['Effect'] not in ['Allow', 'Deny']:
            self.errors.append(f"Statement {idx}: Invalid Effect '{statement['Effect']}'")

        # Check Action or NotAction
        if 'Action' not in statement and 'NotAction' not in statement:
            self.errors.append(f"Statement {idx}: Missing 'Action' or 'NotAction'")

        # Check Resource or NotResource
        if 'Resource' not in statement and 'NotResource' not in statement:
            self.warnings.append(f"Statement {idx}: Missing 'Resource' or 'NotResource'")

        # Check for Sid (recommended)
        if 'Sid' not in statement:
            self.warnings.append(f"Statement {idx}: Missing 'Sid' (recommended for clarity)")

    def _validate_security_best_practices(self, policy: Dict):
        """Validate security best practices"""
        has_mfa_condition = False
        has_source_ip_condition = False
        has_deny_statement = False

        for statement in policy.get('Statement', []):
            effect = statement.get('Effect', '')

            # Check for Deny statements (defense in depth)
            if effect == 'Deny':
                has_deny_statement = True

            # Check for MFA conditions
            condition = statement.get('Condition', {})
            if 'Bool' in condition or 'BoolIfExists' in condition:
                for cond_type in ['Bool', 'BoolIfExists']:
                    if cond_type in condition:
                        if 'aws:MultiFactorAuthPresent' in condition[cond_type]:
                            has_mfa_condition = True

            # Check for source IP conditions
            if 'IpAddress' in condition or 'NotIpAddress' in condition:
                has_source_ip_condition = True

            # Check for wildcard actions (*)
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            for action in actions:
                if action == '*' and effect == 'Allow':
                    self.warnings.append(f"Wildcard action '*' in Allow statement: {statement.get('Sid', 'unnamed')}")

            # Check for wildcard resources (*)
            resources = statement.get('Resource', [])
            if not isinstance(resources, list):
                resources = [resources]
            for resource in resources:
                if resource == '*' and effect == 'Allow':
                    self.warnings.append(f"Wildcard resource '*' in Allow statement: {statement.get('Sid', 'unnamed')}")

        # Recommendations
        if not has_mfa_condition:
            self.info.append("Consider adding MFA requirement conditions for enhanced security")

        if not has_source_ip_condition:
            self.info.append("Consider adding source IP restrictions where applicable")

        if not has_deny_statement:
            self.info.append("Consider adding explicit Deny statements for defense in depth")

    def _validate_pci_dss(self, policy: Dict):
        """Validate PCI DSS compliance requirements"""
        # PCI DSS Requirement 7: Restrict access to cardholder data
        # PCI DSS Requirement 8: Identify and authenticate access

        has_cde_protection = False
        has_security_service_protection = False

        for statement in policy.get('Statement', []):
            # Check for CDE account protection
            condition = statement.get('Condition', {})
            if 'StringEquals' in condition:
                if 'aws:ResourceAccount' in condition['StringEquals']:
                    cde_account = '444455556666'
                    if cde_account in str(condition['StringEquals']['aws:ResourceAccount']):
                        has_cde_protection = True

            # Check for security service protection
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]

            security_actions = [
                'cloudtrail:StopLogging',
                'cloudtrail:DeleteTrail',
                'guardduty:DeleteDetector',
                'securityhub:DisableSecurityHub',
                'config:StopConfigurationRecorder'
            ]

            for action in actions:
                if any(sec_action in action for sec_action in security_actions):
                    if statement.get('Effect') == 'Deny':
                        has_security_service_protection = True

        # PCI DSS recommendations
        if 'cde' in str(policy).lower() or 'cardholder' in str(policy).lower():
            if not has_cde_protection:
                self.warnings.append("PCI DSS: Consider adding explicit CDE account protection")

        if not has_security_service_protection:
            self.info.append("PCI DSS Req 10: Consider protecting security services from deletion/disabling")

    def _check_permissions(self, policy: Dict):
        """Check for overly permissive policies"""
        dangerous_permissions = [
            'iam:PassRole',
            'iam:CreateAccessKey',
            'iam:CreateUser',
            'iam:CreateRole',
            'iam:AttachUserPolicy',
            'iam:AttachRolePolicy',
            'sts:AssumeRole',
            'organizations:LeaveOrganization',
            'kms:ScheduleKeyDeletion'
        ]

        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if not isinstance(actions, list):
                    actions = [actions]

                for action in actions:
                    for dangerous in dangerous_permissions:
                        if dangerous in action:
                            self.warnings.append(f"Potentially dangerous permission: {action}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Validate IAM policies for security and compliance'
    )
    parser.add_argument('--policy', help='Specific policy file to validate')
    parser.add_argument('--directory', default='.', help='Directory containing policy files')
    parser.add_argument('--strict', action='store_true', help='Treat warnings as errors')

    args = parser.parse_args()

    validator = IAMPolicyValidator()
    all_valid = True

    # Validate specific file or all JSON files in directory
    if args.policy:
        policy_files = [args.policy]
    else:
        policy_dir = Path(args.directory)
        policy_files = list(policy_dir.glob('*.json'))
        policy_files.extend(list(policy_dir.glob('irsa-policies/*.json')))

    if not policy_files:
        logger.error(f"No policy files found in {args.directory}")
        return 1

    print(f"\n{'='*60}")
    print(f"IAM Policy Validation Report")
    print(f"{'='*60}\n")

    for policy_file in policy_files:
        is_valid, errors, warnings = validator.validate_policy_file(str(policy_file))

        # Print results
        status = "✓ PASS" if (is_valid and (not args.strict or not warnings)) else "✗ FAIL"
        print(f"{status} - {policy_file}")

        if errors:
            print("  Errors:")
            for error in errors:
                print(f"    • {error}")
            all_valid = False

        if warnings:
            print("  Warnings:")
            for warning in warnings:
                print(f"    • {warning}")
            if args.strict:
                all_valid = False

        if validator.info:
            print("  Recommendations:")
            for info in validator.info:
                print(f"    • {info}")

        print()

    # Summary
    print(f"{'='*60}")
    if all_valid:
        print("✓ All policies validated successfully")
        return 0
    else:
        print("✗ Some policies failed validation")
        return 1

if __name__ == '__main__':
    sys.exit(main())
