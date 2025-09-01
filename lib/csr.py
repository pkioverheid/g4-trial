from .dn import as_name
from .ra import validate


def process(profile, enrollment, keypair, config):

    validate(enrollment, profile)

    subject = as_name(enrollment['subject'])

    csr_path = f"{keypair.basename}.csr"
    keypair.create_csr(profile, subject, csr_path)

    print(f"Private key written to {keypair.privatekeyfile}")
    print(f"CSR written to {csr_path}")
