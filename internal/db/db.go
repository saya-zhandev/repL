package db

import (
	"encoding/json"
	"errors"
	"sync"
)

type StudentRecord struct {
	Name             string  `json:"name"`
	StudentID        string  `json:"student_id"`
	GPA              float64 `json:"gpa"`
	EnrollmentStatus string  `json:"enrollment_status"`
	SSN              string  `json:"ssn"`
}

type EncryptedStudent struct {
	StudentID  string `json:"student_id"`
	Ciphertext []byte `json:"ciphertext"`
	Commitment string `json:"commitment"`
}

// InMemoryDB is a fully Go-native, CGO-free database (works with Vercel serverless)
type InMemoryDB struct {
	mu       sync.RWMutex
	students map[string]EncryptedStudent // key: studentID
}

func NewInMemoryDB() (*InMemoryDB, error) {
	return &InMemoryDB{
		students: make(map[string]EncryptedStudent),
	}, nil
}

// Close is a no-op for in-memory DB
func (s *InMemoryDB) Close() error {
	return nil
}

func (s *InMemoryDB) CreateStudent(student *EncryptedStudent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.students[student.StudentID]; exists {
		return errors.New("student already exists")
	}
	s.students[student.StudentID] = *student
	return nil
}

func (s *InMemoryDB) GetStudent(studentID string) (*EncryptedStudent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	student, exists := s.students[studentID]
	if !exists {
		return nil, errors.New("student not found")
	}
	return &student, nil
}

func (s *InMemoryDB) GetAllEncryptedStudents() ([]EncryptedStudent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var students []EncryptedStudent
	for _, s := range s.students {
		students = append(students, s)
	}
	return students, nil
}

func (sr *StudentRecord) Serialize() ([]byte, error) {
	return json.Marshal(sr)
}

func DeserializeStudentRecord(data []byte) (*StudentRecord, error) {
	var sr StudentRecord
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	if sr.StudentID == "" {
		return nil, errors.New("invalid record")
	}
	return &sr, nil
}

// Keep NewSQLiteDB as a wrapper for backward compatibility during transition
func NewSQLiteDB(dbPath string) (*InMemoryDB, error) {
	return NewInMemoryDB()
}
