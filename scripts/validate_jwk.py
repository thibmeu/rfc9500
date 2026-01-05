#!/usr/bin/env python3
"""
Validate JWK format and cross-format consistency
"""

import json
import base64
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def b64url_decode(data):
    """Decode base64url with proper padding"""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def validate_jwk_structure(jwk_file):
    """Validate JWK structure and encoding"""
    with open(jwk_file) as f:
        jwk = json.load(f)

    errors = []

    if jwk["kty"] == "EC":
        required_fields = ["kty", "crv", "x", "y"]
        if "d" in jwk:  # private key
            required_fields.append("d")

        for field in required_fields:
            if field not in jwk:
                errors.append(f"Missing required field: {field}")

        # Validate base64url encoding
        for field in ["x", "y", "d"]:
            if field in jwk:
                try:
                    decoded = b64url_decode(jwk[field])
                    # Check coordinate sizes
                    if field in ["x", "y"]:
                        expected_size = (
                            32
                            if jwk["crv"] == "P-256"
                            else (48 if jwk["crv"] == "P-384" else 66)
                        )
                        if len(decoded) != expected_size:
                            errors.append(
                                f"Invalid {field} size: {len(decoded)} bytes, expected {expected_size}"
                            )
                except Exception as e:
                    errors.append(f"Invalid {field} encoding: {e}")

    elif jwk["kty"] == "RSA":
        required_fields = ["kty", "n", "e"]
        if "d" in jwk:  # private key
            required_fields.extend(["d", "p", "q", "dp", "dq", "qi"])

        for field in required_fields:
            if field not in jwk:
                errors.append(f"Missing required field: {field}")

        # Validate base64url encoding
        for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"]:
            if field in jwk:
                try:
                    decoded = b64url_decode(jwk[field])
                except Exception as e:
                    errors.append(f"Invalid {field} encoding: {e}")

    else:
        errors.append(f"Unsupported key type: {jwk['kty']}")

    return errors


def verify_jwk_matches_pem(jwk_file, pem_file):
    """Verify JWK matches corresponding PEM file"""
    with open(jwk_file) as f:
        jwk = json.load(f)

    with open(pem_file, "rb") as f:
        pem_data = f.read()

    try:
        if jwk["kty"] == "EC":
            key = serialization.load_pem_public_key(pem_data, backend=default_backend())
            x_bytes = b64url_decode(jwk["x"])
            y_bytes = b64url_decode(jwk["y"])

            key_numbers = key.public_numbers()
            curve_size = (
                32 if jwk["crv"] == "P-256" else (48 if jwk["crv"] == "P-384" else 66)
            )

            return (
                key_numbers.x.to_bytes(curve_size, "big") == x_bytes
                and key_numbers.y.to_bytes(curve_size, "big") == y_bytes
            )

        elif jwk["kty"] == "RSA":
            key = serialization.load_pem_public_key(pem_data, backend=default_backend())
            n_bytes = b64url_decode(jwk["n"])

            key_numbers = key.public_numbers()
            n_size = (key_numbers.n.bit_length() + 7) // 8
            return key_numbers.n.to_bytes(n_size, "big") == n_bytes

    except Exception as e:
        print(f"Error verifying {jwk_file} against {pem_file}: {e}")
        return False


def main():
    jwk_dir = Path("jwk")
    pem_dir = Path("pem")

    if not jwk_dir.exists():
        print("ERROR: jwk directory not found")
        sys.exit(1)

    errors_found = 0

    # Validate all JWK files
    for jwk_file in jwk_dir.glob("*.json"):
        print(f"Validating {jwk_file.name}...")

        # Structure validation
        struct_errors = validate_jwk_structure(jwk_file)
        if struct_errors:
            print(f"  STRUCTURE ERRORS: {', '.join(struct_errors)}")
            errors_found += 1
            continue

        # Cross-format consistency for public keys
        if jwk_file.name.endswith(".pub.json"):
            pem_file = pem_dir / jwk_file.name.replace(".pub.json", ".pub.pem")
            if pem_file.exists():
                if not verify_jwk_matches_pem(jwk_file, pem_file):
                    print(f"  ERROR: JWK does not match PEM format")
                    errors_found += 1
                else:
                    print(f"  OK: Matches PEM format")
            else:
                print(f"  WARNING: No corresponding PEM file found")

    if errors_found > 0:
        print(f"\nVALIDATION FAILED: {errors_found} errors found")
        sys.exit(1)
    else:
        print("\nVALIDATION PASSED: All JWK files are valid")
        sys.exit(0)


if __name__ == "__main__":
    main()
