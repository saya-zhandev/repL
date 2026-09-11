# repL Live Demo Script (LET'I/IDSOL Pitch)

## Step 1: Intro (30 seconds)
> "Today I'm going to show you repL - a system that eliminates the risk of centralized student record breaches by keeping raw data encrypted off-chain, with only cryptographic commitments on Cardano's Midnight privacy blockchain. Even if the database is fully breached, no PII is ever exposed, and third parties only get zero-knowledge verified answers, never raw data."

## Step 2: Registrar adds a student record (1 minute)
1. Open the dashboard at http://localhost:8080
2. Fill in the Registrar form:
   - Name: "Chan Tai Man"
   - Student ID: "LU2024001"
   - GPA: 3.8
   - Enrollment Status: "Active"
   - SSN: "HK12345678"
3. Click "Add Student"
4. Show the result: only a SHA-256 commitment is returned. Explain that the raw record was AES-256-GCM encrypted and stored in the database, and the commitment was appended to the simulated Midnight ledger.

## Step 3: AI agent asks a question (1 minute)
1. In the AI Agent panel, enter student ID "LU2024001"
2. Click "Check Eligibility"
3. Show the result: `{"verified": true}`
4. Explain: The AI agent never saw the raw GPA of 3.8. A real zero-knowledge SNARK proof was generated using gnark that proves the GPA is >= 3.5 without revealing the actual value. This is what would happen when an AI tutor asks if a student is eligible for a scholarship.

## Step 4: Attacker tries to breach the database (1.5 minutes)
1. Click "Launch Breach Attack!" in the Attacker Simulator panel
2. Show the attacker's view: all they get are ciphertext blobs and hashes. No names, no GPAs, no SSNs - everything is encrypted.
3. Click "View On-Chain Ledger" to show what's stored on the "blockchain" (our simulated Midnight ledger): only hashes, no PII whatsoever.
4. Emphasize: Even if a hacker fully compromises both the database and the blockchain, they learn nothing about the students. This solves the 2026 Canvas breach problem that affected 153,000+ people in Hong Kong - there's nothing to steal!

## Step 5: Production roadmap (30 seconds)
> "In production, we would deploy this on the real Midnight testnet using their Compact smart contract language, add proper key management, and build a consent UI for students to control who can ask which questions about their data. This architecture is GDPR and PDPO compliant by design - no sensitive data ever leaves university custody unless it's a zero-knowledge verified answer the student has approved."