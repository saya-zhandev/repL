# repL - Privacy-Preserving Student Records

A hackathon prototype for the LETTI/IDSOL pitch competition that demonstrates privacy-preserving student record management using off-chain encryption, on-chain cryptographic commitments, and zero-knowledge proofs.

## Architecture Overview
- **Off-chain encrypted storage**: Student records are encrypted with AES-256-GCM and stored in a SQLite database
- **Simulated blockchain ledger**: A hash-chained local ledger stores only SHA-256 commitments (simulates Cardano's Midnight network)
- **Zero-knowledge proofs**: Real gnark ZK-SNARK circuit to verify GPA >= threshold without revealing the actual GPA
- **Three-panel demo dashboard**: Registrar, AI Agent Simulator, and Attacker Simulator to demonstrate the privacy guarantees

## Prerequisites
- Go 1.22 or higher
- Git

## Setup Instructions
1. Clone the repository
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Start the server:
   ```bash
   go run cmd/server/main.go
   ```
4. Open your browser and navigate to http://localhost:8080 to access the demo dashboard

## Run Tests
```bash
go test -v
```

## Project Structure
```
repL/
├── cmd/
│   └── server/
│       └── main.go          # Main server entry point
├── internal/
│   ├── db/                  # Database layer
│   ├── encryptor/           # AES encryption and SHA-256 commitments
│   ├── ledger/              # Local hash-chained ledger simulation
│   └── zkcircuit/           # gnark ZK-SNARK circuit for GPA verification
├── frontend/
│   └── index.html           # Three-panel demo dashboard
├── go.mod
├── DEMO.md                  # Live pitch walkthrough script
├── LIMITATIONS.md           # Prototype limitations and production roadmap
└── README.md
```

## Key Features Demonstrated
1. **Registrar**: Add student records that are encrypted and only commitments are stored on the ledger
2. **AI Agent Simulator**: Ask zero-knowledge verified questions (e.g., "is this student eligible for a scholarship?") and only receive true/false
3. **Attacker Simulator**: Demonstrate that even if the database is breached, all sensitive data is encrypted and unreadable

## Important Notes
- The local ledger is a simulation of the Midnight/Cardano anchor layer. In production, this would be replaced with real Midnight smart contracts
- All cryptography used is real: AES-256-GCM for encryption, SHA-256 for commitments, and real gnark ZK-SNARK proofs
- No PII is ever stored on the "blockchain" - only cryptographic commitments