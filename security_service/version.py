"""
security_service/version.py

Three version stamps that appear in every report's provenance:
  CONTRACT_VERSION  - the Flwn-facing API contract (openapi.yaml). Changes inside /v1 are additive only.
  SERVICE_VERSION   - this codebase.
  POLICY_VERSION    - the decision policy (thresholds in core/policy.py). Bump when thresholds change,
                      so a stored decision can always be traced to the policy that produced it.
"""

CONTRACT_VERSION = "1.0.0"
SERVICE_VERSION = "0.1.0"
POLICY_VERSION = "policy-1"
