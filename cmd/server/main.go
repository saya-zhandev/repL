package main

import (
	"log"
	"net/http"
	"repl/internal/db"
	"repl/internal/encryptor"
	"repl/internal/ledger"
	"repl/internal/zkcircuit"
	"strconv"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database
	database, err := db.NewSQLiteDB("repl.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Initialize AES encryptor (in production, use secure key management)
	enc, err := encryptor.NewAES256GCM("this-is-a-32-byte-secret-key-123456")
	if err != nil {
		log.Fatalf("Failed to create encryptor: %v", err)
	}

	// Initialize ledger simulator
	localLedger := ledger.NewLocalLedger()
	if err := localLedger.Load(); err != nil {
		log.Printf("No existing ledger found, creating new one: %v", err)
	}

	// Initialize ZK circuit
	zkProver, err := zkcircuit.NewGPAThresholdProver()
	if err != nil {
		log.Fatalf("Failed to initialize ZK prover: %v", err)
	}

	// Setup Gin router
	r := gin.Default()

	// Serve frontend static files
	r.StaticFS("/", http.Dir("frontend"))

	// API routes
	api := r.Group("/api")
	{
		// Registrar: create student record
		api.POST("/students", func(c *gin.Context) {
			var req struct {
				Name             string  `json:"name"`
				StudentID        string  `json:"student_id"`
				GPA              float64 `json:"gpa"`
				EnrollmentStatus string  `json:"enrollment_status"`
				SSN              string  `json:"ssn"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// Create plaintext record
			record := db.StudentRecord{
				Name:             req.Name,
				StudentID:        req.StudentID,
				GPA:              req.GPA,
				EnrollmentStatus: req.EnrollmentStatus,
				SSN:              req.SSN,
			}

			// Serialize and encrypt record
			plaintext, err := record.Serialize()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize record"})
				return
			}

			ciphertext, err := enc.Encrypt(plaintext)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
				return
			}

			// Compute SHA-256 commitment
			commitment := encryptor.ComputeSHA256Commitment(plaintext)

			// Store encrypted record in DB
			dbRecord := db.EncryptedStudent{
				StudentID:  req.StudentID,
				Ciphertext: ciphertext,
				Commitment: commitment,
			}
			if err := database.CreateStudent(&dbRecord); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store record"})
				return
			}

			// Append commitment to ledger (SIMULATES Midnight/Cardano anchor layer)
			if err := localLedger.Append(commitment); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to append to ledger"})
				return
			}
			if err := localLedger.Save(); err != nil {
				log.Printf("Failed to save ledger: %v", err)
			}

			c.JSON(http.StatusCreated, gin.H{"status": "record created", "commitment": commitment})
		})

		// ZK verification endpoint
		api.POST("/verify-attribute", func(c *gin.Context) {
			var req struct {
				StudentID string  `json:"student_id"`
				Attribute string  `json:"attribute"`
				Threshold float64 `json:"threshold"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// Retrieve encrypted record
			dbRecord, err := database.GetStudent(req.StudentID)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "student not found"})
				return
			}

			// Decrypt to get plaintext GPA (only done OFF-CHAIN, never exposed)
			plaintext, err := enc.Decrypt(dbRecord.Ciphertext)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "decryption failed"})
				return
			}

			record, err := db.DeserializeStudentRecord(plaintext)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deserialize record"})
				return
			}

			// Only support GPA threshold for MVP (one working real proof)
			if req.Attribute != "gpa" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "only 'gpa' attribute supported in MVP"})
				return
			}

			// Generate and verify ZK proof that GPA >= threshold
			verified, err := zkProver.VerifyGPAThreshold(record.GPA, req.Threshold)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "ZK proof generation/verification failed"})
				return
			}

			// Append verification result to ledger (SIMULATES on-chain proof verification)
			verificationCommitment := encryptor.ComputeSHA256Commitment([]byte(req.StudentID + ":" + strconv.FormatBool(verified)))
			if err := localLedger.Append(verificationCommitment); err != nil {
				log.Printf("Failed to append verification to ledger: %v", err)
			}
			localLedger.Save()

			c.JSON(http.StatusOK, gin.H{"verified": verified})
		})

		// Get ledger entries (on-chain data - only hashes!)
		api.GET("/ledger", func(c *gin.Context) {
			entries := localLedger.GetEntries()
			c.JSON(http.StatusOK, gin.H{
				"ledger_length": len(entries),
				"entries":       entries,
				"note":          "// SIMULATES Midnight/Cardano anchor layer: only cryptographic commitments are stored on-chain, no PII ever",
			})
		})

		// Attacker simulator: get raw encrypted records (demonstrates breach scenario)
		api.GET("/attacker/raw-records", func(c *gin.Context) {
			allRecords, err := database.GetAllEncryptedStudents()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch records"})
				return
			}
			// Return exactly what an attacker would see: ciphertext blobs and hashes
			c.JSON(http.StatusOK, gin.H{
				"attacker_view":     "You are an attacker who breached the database! Here's what you get:",
				"encrypted_records": allRecords,
				"note":              "All sensitive data is encrypted; you can't read any PII from the ciphertexts!",
			})
		})
	}

	log.Println("repL server starting on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
