#!/usr/bin/env python3
"""
Envelope Encryption Example with AWS KMS
Author: Evgeniy Gantman
Purpose: Demonstrate envelope encryption pattern for secure data encryption
PCI DSS: Requirement 3.4 (Render PAN unreadable), Requirement 3.5 (Key Management)

Envelope Encryption Pattern:
1. Generate Data Encryption Key (DEK) from KMS
2. Use DEK to encrypt data locally (fast, no network calls)
3. Store encrypted DEK alongside encrypted data
4. To decrypt: Use KMS to decrypt DEK, then decrypt data locally
"""

import argparse
import base64
import json
import logging
import os
import sys
from typing import Dict, Tuple

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class EnvelopeEncryption:
    """
    Envelope encryption implementation using AWS KMS

    This pattern provides:
    - Fast encryption (local, not API-limited)
    - Centralized key management (KMS)
    - Audit trail (CloudTrail logs all KMS operations)
    - Key rotation support (KMS automatic rotation)
    """

    def __init__(self, kms_key_id: str, region: str = 'us-east-1'):
        """
        Initialize envelope encryption handler

        Args:
            kms_key_id: KMS CMK ID or alias (e.g., 'alias/rds-prod')
            region: AWS region
        """
        self.kms_key_id = kms_key_id
        self.region = region

        try:
            self.kms_client = boto3.client('kms', region_name=region)
        except Exception as e:
            logger.error(f"Failed to create KMS client: {str(e)}")
            raise

    def encrypt_data(self, plaintext_data: bytes, encryption_context: Dict[str, str] = None) -> Dict[str, str]:
        """
        Encrypt data using envelope encryption

        Args:
            plaintext_data: Data to encrypt
            encryption_context: Additional authenticated data (AAD) for KMS

        Returns:
            Dictionary containing encrypted data and encrypted DEK
        """
        if not plaintext_data:
            raise ValueError("Plaintext data cannot be empty")

        try:
            # Step 1: Generate Data Encryption Key (DEK) from KMS
            logger.info(f"Generating DEK from KMS key: {self.kms_key_id}")

            generate_params = {
                'KeyId': self.kms_key_id,
                'KeySpec': 'AES_256'
            }

            # Add encryption context for additional security
            if encryption_context:
                generate_params['EncryptionContext'] = encryption_context

            response = self.kms_client.generate_data_key(**generate_params)

            # Plaintext DEK (will be used to encrypt data, then discarded)
            plaintext_dek = response['Plaintext']

            # Encrypted DEK (will be stored with encrypted data)
            encrypted_dek = response['CiphertextBlob']

            logger.info(f"DEK generated. Plaintext DEK size: {len(plaintext_dek)} bytes")

            # Step 2: Use plaintext DEK to encrypt data locally
            # Using Fernet (AES-128 in CBC mode with HMAC authentication)
            # In production, you might use AES-256-GCM directly

            # Convert DEK to Fernet-compatible key (32 bytes, base64-encoded)
            fernet_key = base64.urlsafe_b64encode(plaintext_dek)
            fernet = Fernet(fernet_key)

            encrypted_data = fernet.encrypt(plaintext_data)

            logger.info(f"Data encrypted. Original size: {len(plaintext_data)}, "
                       f"Encrypted size: {len(encrypted_data)}")

            # Step 3: Return encrypted data and encrypted DEK
            # In practice, store these together in your database or S3
            result = {
                'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                'encrypted_dek': base64.b64encode(encrypted_dek).decode('utf-8'),
                'kms_key_id': self.kms_key_id,
                'algorithm': 'AES-256-Fernet',
                'encryption_context': encryption_context or {}
            }

            # Security: Zero out plaintext DEK from memory
            plaintext_dek = None
            fernet_key = None

            return result

        except ClientError as e:
            logger.error(f"KMS error during encryption: {e.response['Error']['Code']}")
            raise
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise

    def decrypt_data(self, encrypted_package: Dict[str, str]) -> bytes:
        """
        Decrypt data using envelope encryption

        Args:
            encrypted_package: Dictionary from encrypt_data() containing encrypted data and DEK

        Returns:
            Decrypted plaintext data
        """
        try:
            # Extract components
            encrypted_data_b64 = encrypted_package['encrypted_data']
            encrypted_dek_b64 = encrypted_package['encrypted_dek']
            encryption_context = encrypted_package.get('encryption_context', {})

            encrypted_data = base64.b64decode(encrypted_data_b64)
            encrypted_dek = base64.b64decode(encrypted_dek_b64)

            # Step 1: Use KMS to decrypt the Data Encryption Key
            logger.info("Decrypting DEK using KMS")

            decrypt_params = {
                'CiphertextBlob': encrypted_dek
            }

            # Must provide same encryption context used during encryption
            if encryption_context:
                decrypt_params['EncryptionContext'] = encryption_context

            response = self.kms_client.decrypt(**decrypt_params)
            plaintext_dek = response['Plaintext']

            # Verify the correct key was used
            if response['KeyId'] != self.kms_key_id and not response['KeyId'].endswith(self.kms_key_id):
                logger.warning(f"DEK was encrypted with different key: {response['KeyId']}")

            # Step 2: Use plaintext DEK to decrypt data locally
            fernet_key = base64.urlsafe_b64encode(plaintext_dek)
            fernet = Fernet(fernet_key)

            plaintext_data = fernet.decrypt(encrypted_data)

            logger.info(f"Data decrypted successfully. Size: {len(plaintext_data)} bytes")

            # Security: Zero out plaintext DEK from memory
            plaintext_dek = None
            fernet_key = None

            return plaintext_data

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidCiphertextException':
                logger.error("DEK decryption failed: Invalid ciphertext or wrong key")
            elif error_code == 'AccessDeniedException':
                logger.error("Access denied: Check IAM permissions for kms:Decrypt")
            else:
                logger.error(f"KMS error during decryption: {error_code}")
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise

    def encrypt_file(self, input_file: str, output_file: str, encryption_context: Dict[str, str] = None):
        """
        Encrypt a file using envelope encryption

        Args:
            input_file: Path to plaintext file
            output_file: Path to output encrypted file (JSON format)
            encryption_context: Additional authenticated data
        """
        try:
            # Read plaintext file
            with open(input_file, 'rb') as f:
                plaintext_data = f.read()

            logger.info(f"Read {len(plaintext_data)} bytes from {input_file}")

            # Encrypt using envelope encryption
            encrypted_package = self.encrypt_data(plaintext_data, encryption_context)

            # Write encrypted package to file
            with open(output_file, 'w') as f:
                json.dump(encrypted_package, f, indent=2)

            logger.info(f"Encrypted file saved to {output_file}")

        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            raise
        except Exception as e:
            logger.error(f"File encryption failed: {str(e)}")
            raise

    def decrypt_file(self, input_file: str, output_file: str):
        """
        Decrypt a file encrypted with envelope encryption

        Args:
            input_file: Path to encrypted file (JSON format)
            output_file: Path to output plaintext file
        """
        try:
            # Read encrypted package
            with open(input_file, 'r') as f:
                encrypted_package = json.load(f)

            logger.info(f"Read encrypted package from {input_file}")

            # Decrypt using envelope encryption
            plaintext_data = self.decrypt_data(encrypted_package)

            # Write plaintext file
            with open(output_file, 'wb') as f:
                f.write(plaintext_data)

            logger.info(f"Decrypted file saved to {output_file}")

        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            raise
        except Exception as e:
            logger.error(f"File decryption failed: {str(e)}")
            raise


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Envelope encryption example with AWS KMS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file
  ./envelope-encryption-example.py encrypt \
    --key-id alias/s3-prod \
    --input sensitive-data.txt \
    --output encrypted-data.json

  # Decrypt a file
  ./envelope-encryption-example.py decrypt \
    --key-id alias/s3-prod \
    --input encrypted-data.json \
    --output decrypted-data.txt

  # With encryption context (recommended for PCI DSS)
  ./envelope-encryption-example.py encrypt \
    --key-id alias/rds-cde \
    --input cardholder-data.csv \
    --output encrypted-chd.json \
    --context environment=production data-class=pci-cardholder-data
        """
    )

    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('--key-id', required=True, help='KMS Key ID or alias')
    parser.add_argument('--input', required=True, help='Input file')
    parser.add_argument('--output', required=True, help='Output file')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--context', nargs='*', help='Encryption context (key=value pairs)')

    args = parser.parse_args()

    # Parse encryption context
    encryption_context = {}
    if args.context:
        for ctx in args.context:
            if '=' not in ctx:
                logger.error(f"Invalid context format: {ctx} (expected key=value)")
                return 1
            key, value = ctx.split('=', 1)
            encryption_context[key] = value

    # Initialize envelope encryption
    envelope = EnvelopeEncryption(args.key_id, args.region)

    try:
        if args.action == 'encrypt':
            envelope.encrypt_file(args.input, args.output, encryption_context or None)
            print(f"\n✓ File encrypted successfully: {args.output}")
            print(f"  KMS Key: {args.key_id}")
            if encryption_context:
                print(f"  Encryption Context: {encryption_context}")
        else:
            envelope.decrypt_file(args.input, args.output)
            print(f"\n✓ File decrypted successfully: {args.output}")

        return 0

    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
