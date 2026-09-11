package db

import (
	"encoding/json"
	"errors"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
)

type StudentRecord struct {
	Name             string  `json:"name"`
	StudentID        string  `json:"student_id"`
	GPA              float64 `json:"gpa"`
	EnrollmentStatus string  `json:"enrollment_status"`
	SSN              string  `json:"ssn"`
}

type EncryptedStudent struct {
	gorm.Model
	StudentID  string `gorm:"unique_index"`
	Ciphertext []byte `json:"ciphertext"`
	Commitment string `json:"commitment"`
}

type SQLiteDB struct {
	db *gorm.DB
}

func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	db.AutoMigrate(&EncryptedStudent{})
	return &SQLiteDB{db: db}, nil
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

func (s *SQLiteDB) CreateStudent(student *EncryptedStudent) error {
	return s.db.Create(student).Error
}

func (s *SQLiteDB) GetStudent(studentID string) (*EncryptedStudent, error) {
	var student EncryptedStudent
	if err := s.db.Where("student_id = ?", studentID).First(&student).Error; err != nil {
		return nil, err
	}
	return &student, nil
}

func (s *SQLiteDB) GetAllEncryptedStudents() ([]EncryptedStudent, error) {
	var students []EncryptedStudent
	if err := s.db.Find(&students).Error; err != nil {
		return nil, err
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
