package ledger

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
)

// SIMULATES the Midnight/Cardano anchor layer for demo purposes
// Production would submit this commitment via a Compact smart contract on Midnight
type LedgerEntry struct {
	Index        uint64 `json:"index"`
	PreviousHash string `json:"previous_hash"`
	Data         string `json:"data"` // Only commitments/hashes, never plaintext
	CurrentHash  string `json:"current_hash"`
}

type LocalLedger struct {
	Entries []LedgerEntry `json:"entries"`
}

func NewLocalLedger() *LocalLedger {
	return &LocalLedger{
		Entries: []LedgerEntry{},
	}
}

func (l *LocalLedger) Load() error {
	data, err := os.ReadFile("ledger.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, l)
}

func (l *LocalLedger) Save() error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("ledger.json", data, 0644)
}

func (l *LocalLedger) Append(data string) error {
	var previousHash string
	var index uint64 = 0
	if len(l.Entries) > 0 {
		lastEntry := l.Entries[len(l.Entries)-1]
		previousHash = lastEntry.CurrentHash
		index = lastEntry.Index + 1
	}

	// Compute current hash by hashing previous hash + new data
	hashInput := previousHash + data
	currentHashBytes := sha256.Sum256([]byte(hashInput))
	currentHash := string(currentHashBytes[:])

	newEntry := LedgerEntry{
		Index:        index,
		PreviousHash: previousHash,
		Data:         data,
		CurrentHash:  currentHash,
	}
	l.Entries = append(l.Entries, newEntry)
	return nil
}

func (l *LocalLedger) VerifyChain() (bool, error) {
	for i := 1; i < len(l.Entries); i++ {
		prevEntry := l.Entries[i-1]
		currEntry := l.Entries[i]
		if currEntry.PreviousHash != prevEntry.CurrentHash {
			return false, errors.New("chain broken at index " + string(rune(i)))
		}
		// Verify current hash is correct
		expectedInput := prevEntry.CurrentHash + currEntry.Data
		hash := sha256.Sum256([]byte(expectedInput))
		expectedHash := string(hash[:])
		if currEntry.CurrentHash != expectedHash {
			return false, errors.New("invalid hash at index " + string(rune(i)))
		}
	}
	return true, nil
}

func (l *LocalLedger) GetEntries() []LedgerEntry {
	return l.Entries
}
