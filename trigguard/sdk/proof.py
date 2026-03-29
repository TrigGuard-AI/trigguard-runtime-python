from trigguard.proof.http import decode_proof_header


def verify_execution_proof_header(value, verifier) -> bool:
    proof = decode_proof_header(value)
    result = verifier.verify(proof)
    return result.valid


def extract_and_verify_proof_from_response(response, verifier):
    header = response.headers.get("X-TrigGuard-Proof")
    if not header:
        return False
    return verify_execution_proof_header(header, verifier)
