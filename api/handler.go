package handler

import (
	"log"
	"net/http"
	"repl/internal/db"
	"repl/internal/encryptor"
	"repl/internal/ledger"
	"repl/internal/zkcircuit"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	router   *gin.Engine
	initOnce sync.Once
	initErr  error
)

func initRouter() error {
	initOnce.Do(func() {
		// Initialize CGO-free in-memory database (Vercel-compatible)
		database, err := db.NewInMemoryDB()
		if err != nil {
			initErr = err
			return
		}

		// Initialize AES encryptor (32-byte key for AES-256-GCM)
		enc, err := encryptor.NewAES256GCM("this-is-a-32-byte-secret-key-123456")
		if err != nil {
			initErr = err
			return
		}

		// Initialize ledger simulator
		localLedger := ledger.NewLocalLedger()
		if err := localLedger.Load(); err != nil {
			log.Printf("No existing ledger found, creating new one: %v", err)
		}

		// Initialize ZK circuit prover
		zkProver, err := zkcircuit.NewGPAThresholdProver()
		if err != nil {
			initErr = err
			return
		}

		// Setup Gin router
		r := gin.Default()

		// Serve frontend static files
		r.StaticFS("/", http.Dir("frontend"))

		// API routes
		api := r.Group("/api")
		{
			// Create student record endpoint
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

				// Create and serialize plaintext record
				record := db.StudentRecord{
					Name:             req.Name,
					StudentID:        req.StudentID,
					GPA:              req.GPA,
					EnrollmentStatus: req.EnrollmentStatus,
					SSN:              req.SSN,
				}

				plaintext, err := record.Serialize()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize record"})
					return
				}

				// Encrypt record
				ciphertext, err := enc.Encrypt(plaintext)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
					return
				}

				// Compute cryptographic commitment
				commitment := encryptor.ComputeSHA256Commitment(plaintext)

				// Store encrypted record
				dbRecord := db.EncryptedStudent{
					StudentID:  req.StudentID,
					Ciphertext: ciphertext,
					Commitment: commitment,
				}
				if err := database.CreateStudent(&dbRecord); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store record"})
					return
				}

				// Append to ledger
				if err := localLedger.Append(commitment); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to append to ledger"})
					return
				}
				localLedger.Save()

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

				// Retrieve and decrypt record
				dbRecord, err := database.GetStudent(req.StudentID)
				if err != nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "student not found"})
					return
				}

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

				// Only support GPA threshold in MVP
				if req.Attribute != "gpa" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "only 'gpa' attribute supported"})
					return
				}

				// Generate and verify ZK proof
				verified, err := zkProver.VerifyGPAThreshold(record.GPA, req.Threshold)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "ZK proof failed"})
					return
				}

				// Append verification result to ledger
				verificationCommitment := encryptor.ComputeSHA256Commitment([]byte(req.StudentID + ":" + strconv.FormatBool(verified)))
				if err := localLedger.Append(verificationCommitment); err != nil {
					log.Printf("Failed to append verification: %v", err)
				}
				localLedger.Save()

				c.JSON(http.StatusOK, gin.H{"verified": verified})
			})

			// Get ledger entries (only hashes, no PII)
			api.GET("/ledger", func(c *gin.Context) {
				entries := localLedger.GetEntries()
				c.JSON(http.StatusOK, gin.H{
					"ledger_length": len(entries),
					"entries":       entries,
					"note":          "Only cryptographic commitments stored, no PII exposed!",
				})
			})

			// Attacker view simulation
			api.GET("/attacker/raw-records", func(c *gin.Context) {
				allRecords, err := database.GetAllEncryptedStudents()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch records"})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"attacker_view":     "You breached the database! This is all you get:",
					"encrypted_records": allRecords,
					"note":              "All sensitive data is encrypted; no PII can be read!",
				})
			})
		} // close api group block

		// Save router to global variable
		router = r
	}) // close initOnce.Do()
	return initErr
}

// Handler is the exported function required by Vercel's Go serverless runtime
func Handler(w http.ResponseWriter, r *http.Request) {
	if err := initRouter(); err != nil {
		http.Error(w, "Failed to initialize server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	router.ServeHTTP(w, r)
}
