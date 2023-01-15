# AWS KMS Encryption

| File | Purpose |
|------|---------|
| kms-keys.tf | CMK definitions for each service |
| key-rotation-policy.tf | Automatic annual key rotation |
| cross-account-sharing.tf | Cross-account key grants |
| cloudhsm-integration.tf | CloudHSM custom key store |
| envelope-encryption-example.py | Envelope encryption pattern |
| key-audit-logging.py | KMS usage audit reports |
| key-lifecycle.yaml | Key lifecycle policy definitions |
| rotate-keys.sh | Manual rotation script |
