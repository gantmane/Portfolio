#!/usr/bin/env python3
"""
Continuous Verification for Zero Trust
Author: Evgeniy Gantman
Purpose: Runtime access validation and risk-based authentication
Framework: NIST 800-207 Principle 7, PCI DSS 10.2
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import boto3
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from google.cloud import logging as gcp_logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AccessRequest:
    """Represents an access request to be evaluated"""
    user_id: str
    user_email: str
    device_id: str
    source_ip: str
    resource_type: str
    resource_id: str
    action: str
    timestamp: datetime
    mfa_verified: bool
    device_compliant: bool
    risk_score: int


@dataclass
class RiskFactor:
    """Risk factor that contributes to overall risk score"""
    name: str
    score: int
    description: str


class ContinuousVerification:
    """Main class for continuous verification"""

    def __init__(self):
        self.azure_credential = DefaultAzureCredential()
        self.aws_session = boto3.Session()
        self.gcp_client = gcp_logging.Client()

        # Azure AD Identity Protection client
        self.identity_protection_endpoint = "https://graph.microsoft.com/v1.0"

        # Thresholds
        self.LOW_RISK_THRESHOLD = 20
        self.MEDIUM_RISK_THRESHOLD = 50
        self.HIGH_RISK_THRESHOLD = 80

    def evaluate_access_request(self, request: AccessRequest) -> Dict:
        """
        Evaluate an access request using continuous verification

        Returns:
            dict: {
                'allowed': bool,
                'risk_score': int,
                'risk_factors': List[RiskFactor],
                'required_actions': List[str],
                'audit_log': dict
            }
        """
        logger.info(f"Evaluating access request for user {request.user_email}")

        # Calculate risk score
        risk_factors = self._calculate_risk_factors(request)
        total_risk = sum(rf.score for rf in risk_factors)

        # Determine if access should be allowed
        allowed = self._determine_access(request, total_risk)

        # Generate required actions if access is denied or risk is elevated
        required_actions = self._generate_required_actions(request, total_risk)

        # Create audit log
        audit_log = self._create_audit_log(request, allowed, total_risk, risk_factors)

        # Send audit log to SIEM
        self._send_to_siem(audit_log)

        result = {
            'allowed': allowed,
            'risk_score': total_risk,
            'risk_factors': [rf.__dict__ for rf in risk_factors],
            'required_actions': required_actions,
            'audit_log': audit_log
        }

        logger.info(f"Access decision for {request.user_email}: "
                   f"allowed={allowed}, risk_score={total_risk}")

        return result

    def _calculate_risk_factors(self, request: AccessRequest) -> List[RiskFactor]:
        """Calculate all risk factors for the request"""
        risk_factors = []

        # User risk factors
        risk_factors.extend(self._evaluate_user_risk(request))

        # Device risk factors
        risk_factors.extend(self._evaluate_device_risk(request))

        # Network risk factors
        risk_factors.extend(self._evaluate_network_risk(request))

        # Behavioral risk factors
        risk_factors.extend(self._evaluate_behavioral_risk(request))

        # Resource sensitivity risk factors
        risk_factors.extend(self._evaluate_resource_risk(request))

        return risk_factors

    def _evaluate_user_risk(self, request: AccessRequest) -> List[RiskFactor]:
        """Evaluate user-specific risk factors"""
        factors = []

        # Check if user has MFA
        if not request.mfa_verified:
            factors.append(RiskFactor(
                name="MFA Not Verified",
                score=50,
                description="User has not completed MFA for this session"
            ))

        # Check Azure AD Identity Protection risk level
        user_risk = self._get_azure_ad_risk_level(request.user_id)
        if user_risk == "high":
            factors.append(RiskFactor(
                name="High User Risk (Azure AD Identity Protection)",
                score=40,
                description="Azure AD Identity Protection flagged this user as high risk"
            ))
        elif user_risk == "medium":
            factors.append(RiskFactor(
                name="Medium User Risk (Azure AD Identity Protection)",
                score=20,
                description="Azure AD Identity Protection flagged this user as medium risk"
            ))

        # Check password age
        password_age_days = self._get_password_age_days(request.user_id)
        if password_age_days > 90:
            factors.append(RiskFactor(
                name="Stale Password",
                score=15,
                description=f"Password has not been changed in {password_age_days} days"
            ))

        return factors

    def _evaluate_device_risk(self, request: AccessRequest) -> List[RiskFactor]:
        """Evaluate device-specific risk factors"""
        factors = []

        # Check if device is compliant
        if not request.device_compliant:
            factors.append(RiskFactor(
                name="Non-Compliant Device",
                score=40,
                description="Device does not meet Intune compliance requirements"
            ))

        # Check device last check-in
        last_checkin_hours = self._get_device_last_checkin(request.device_id)
        if last_checkin_hours > 48:
            factors.append(RiskFactor(
                name="Device Not Recently Checked In",
                score=25,
                description=f"Device last checked in {last_checkin_hours} hours ago"
            ))
        elif last_checkin_hours > 24:
            factors.append(RiskFactor(
                name="Device Check-In Delayed",
                score=10,
                description=f"Device last checked in {last_checkin_hours} hours ago"
            ))

        return factors

    def _evaluate_network_risk(self, request: AccessRequest) -> List[RiskFactor]:
        """Evaluate network-specific risk factors"""
        factors = []

        # Check if IP is from trusted location
        if not self._is_trusted_ip(request.source_ip):
            factors.append(RiskFactor(
                name="Non-Corporate IP Address",
                score=15,
                description=f"Access from non-corporate IP: {request.source_ip}"
            ))

        # Check against threat intelligence
        threat_intel = self._check_threat_intelligence(request.source_ip)
        if threat_intel['malicious']:
            factors.append(RiskFactor(
                name="Malicious IP Detected",
                score=100,  # Immediate block
                description=f"IP {request.source_ip} is on malicious IP list"
            ))
        elif threat_intel['suspicious']:
            factors.append(RiskFactor(
                name="Suspicious IP Detected",
                score=40,
                description=f"IP {request.source_ip} is flagged as suspicious"
            ))

        return factors

    def _evaluate_behavioral_risk(self, request: AccessRequest) -> List[RiskFactor]:
        """Evaluate behavioral risk factors"""
        factors = []

        # Check for impossible travel
        if self._detect_impossible_travel(request.user_id, request.source_ip):
            factors.append(RiskFactor(
                name="Impossible Travel Detected",
                score=60,
                description="User location changed faster than physically possible"
            ))

        # Check for unusual access pattern
        if self._is_unusual_access_time(request.user_id, request.timestamp):
            factors.append(RiskFactor(
                name="Unusual Access Time",
                score=20,
                description=f"Access at unusual time: {request.timestamp.strftime('%H:%M')}"
            ))

        # Check if this is first access to resource
        if self._is_first_resource_access(request.user_id, request.resource_id):
            factors.append(RiskFactor(
                name="First Access to Resource",
                score=15,
                description="User has never accessed this resource before"
            ))

        return factors

    def _evaluate_resource_risk(self, request: AccessRequest) -> List[RiskFactor]:
        """Evaluate resource sensitivity risk factors"""
        factors = []

        # Check resource classification
        classification = self._get_resource_classification(request.resource_id)
        if classification == "restricted":
            factors.append(RiskFactor(
                name="Restricted Resource",
                score=0,  # Not a risk, but requires additional verification
                description="Resource contains cardholder data (PCI DSS)"
            ))
        elif classification == "confidential":
            factors.append(RiskFactor(
                name="Confidential Resource",
                score=0,
                description="Resource contains confidential data"
            ))

        return factors

    def _determine_access(self, request: AccessRequest, risk_score: int) -> bool:
        """Determine if access should be allowed based on risk score"""

        # Always block if risk is very high
        if risk_score >= self.HIGH_RISK_THRESHOLD:
            return False

        # Allow low risk with basic authentication
        if risk_score < self.LOW_RISK_THRESHOLD:
            return True

        # Medium risk requires MFA and compliant device
        if risk_score < self.MEDIUM_RISK_THRESHOLD:
            return request.mfa_verified and request.device_compliant

        # High risk requires additional verification
        return False

    def _generate_required_actions(self, request: AccessRequest, risk_score: int) -> List[str]:
        """Generate list of required actions to gain access"""
        actions = []

        if not request.mfa_verified:
            actions.append("Complete multi-factor authentication")

        if not request.device_compliant:
            actions.append("Ensure device meets compliance requirements (encryption, updates, etc.)")

        if risk_score >= self.MEDIUM_RISK_THRESHOLD:
            actions.append("Contact security team for manual approval")

        if risk_score >= self.HIGH_RISK_THRESHOLD:
            actions.append("Access blocked due to high risk. Contact security team immediately.")

        return actions

    def _create_audit_log(self, request: AccessRequest, allowed: bool,
                         risk_score: int, risk_factors: List[RiskFactor]) -> Dict:
        """Create comprehensive audit log"""
        return {
            'timestamp': request.timestamp.isoformat(),
            'user_id': request.user_id,
            'user_email': request.user_email,
            'device_id': request.device_id,
            'source_ip': request.source_ip,
            'resource_type': request.resource_type,
            'resource_id': request.resource_id,
            'action': request.action,
            'allowed': allowed,
            'risk_score': risk_score,
            'risk_factors': [rf.__dict__ for rf in risk_factors],
            'mfa_verified': request.mfa_verified,
            'device_compliant': request.device_compliant,
            'framework': 'NIST-800-207',
            'compliance': 'PCI-DSS-10.2'
        }

    def _send_to_siem(self, audit_log: Dict):
        """Send audit log to SIEM (Wazuh)"""
        try:
            # In production, send to Wazuh API
            logger.info(f"Sending audit log to SIEM: {json.dumps(audit_log)}")
            # requests.post('https://wazuh.example.com/api/events', json=audit_log)
        except Exception as e:
            logger.error(f"Failed to send audit log to SIEM: {e}")

    # Helper methods (stubs - would be implemented with actual API calls)

    def _get_azure_ad_risk_level(self, user_id: str) -> str:
        """Get user risk level from Azure AD Identity Protection"""
        # In production: query Azure AD Identity Protection API
        return "low"

    def _get_password_age_days(self, user_id: str) -> int:
        """Get number of days since password was last changed"""
        # In production: query Azure AD
        return 45

    def _get_device_last_checkin(self, device_id: str) -> int:
        """Get hours since device last checked in with Intune"""
        # In production: query Intune API
        return 2

    def _is_trusted_ip(self, ip: str) -> bool:
        """Check if IP is from trusted location"""
        trusted_ranges = [
            "203.0.113.0/24",  # Corporate HQ
            "198.51.100.0/24",  # Remote office
        ]
        # In production: use ipaddress module to check ranges
        return False

    def _check_threat_intelligence(self, ip: str) -> Dict:
        """Check IP against threat intelligence feeds"""
        # In production: query threat intelligence APIs
        return {'malicious': False, 'suspicious': False}

    def _detect_impossible_travel(self, user_id: str, current_ip: str) -> bool:
        """Detect if user traveled faster than physically possible"""
        # In production: compare current and previous locations
        return False

    def _is_unusual_access_time(self, user_id: str, timestamp: datetime) -> bool:
        """Check if access time is unusual for this user"""
        # In production: analyze historical access patterns
        hour = timestamp.hour
        return hour < 6 or hour > 22  # Outside 6 AM - 10 PM

    def _is_first_resource_access(self, user_id: str, resource_id: str) -> bool:
        """Check if this is first time user accesses this resource"""
        # In production: query access history
        return False

    def _get_resource_classification(self, resource_id: str) -> str:
        """Get data classification of resource"""
        # In production: query resource tags/labels
        return "internal"


def main():
    """Example usage"""
    verifier = ContinuousVerification()

    # Example access request
    request = AccessRequest(
        user_id="12345678-1234-1234-1234-123456789012",
        user_email="john.doe@examplepay.com",
        device_id="device-abc123",
        source_ip="203.0.113.50",
        resource_type="database",
        resource_id="prod-payment-db",
        action="query",
        timestamp=datetime.now(),
        mfa_verified=True,
        device_compliant=True,
        risk_score=0
    )

    # Evaluate request
    result = verifier.evaluate_access_request(request)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
