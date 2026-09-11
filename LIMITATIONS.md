# repL Prototype Limitations

This is a hackathon prototype - here's what would need to be addressed for production:

## 1. Cryptographic Limitations
- The AES key is hardcoded in this prototype. In production, we'd use a secure key management system (KMS) like AWS KMS or HashiCorp Vault.
- The ZK circuit only supports GPA threshold checks. A production system would support more attributes and complex conditions.
- We use SHA-256 for commitments; in a real Midnight deployment, we'd use Midnight's native cryptographic primitives.

## 2. Privacy & Compliance
- This prototype stores only hashes on the simulated ledger, which is critical for GDPR/PDPO compliance - no personal data is ever placed on a public blockchain. In a real deployment, this is enforced by Midnight's privacy protocols.
- The access control layer is a stretch goal that wasn't implemented in this MVP; production would need a robust consent management system.

## 3. Performance
- ZK proof generation has overhead in this prototype. Optimized ZK libraries and Midnight's native proof verification would reduce this in production.
- The ledger simulation is in-memory and file-based. A real blockchain deployment would handle thousands of transactions per second.

## 4. Next Steps for Pilot
1. Audit all cryptographic implementations by a third party
2. Deploy a testnet version on Midnight's public testnet
3. Implement proper key management and HSM integration
4. Build a student consent UI to manage access to their records
5. Integrate with real university student information systems