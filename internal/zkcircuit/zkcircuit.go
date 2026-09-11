package zkcircuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// GPAThresholdCircuit proves that a secret GPA is >= a public threshold without revealing GPA
type GPAThresholdCircuit struct {
	Threshold frontend.Variable `gnark:",public"`
	GPA       frontend.Variable `gnark:",secret"`
}

func (c *GPAThresholdCircuit) Define(api frontend.API) error {
	// Enforce GPA >= Threshold - this is the core zero-knowledge condition
	api.AssertIsLessOrEqual(c.Threshold, c.GPA)
	return nil
}

type GPAThresholdProver struct {
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	ccs constraint.ConstraintSystem
}

func NewGPAThresholdProver() (*GPAThresholdProver, error) {
	// Compile the circuit using the correct ecc.BN254.ScalarField() for gnark v0.10.0
	var circuit GPAThresholdCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, err
	}

	// Generate proving and verifying keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}

	return &GPAThresholdProver{
		pk:  pk,
		vk:  vk,
		ccs: ccs,
	}, nil
}

func (p *GPAThresholdProver) VerifyGPAThreshold(gpa, threshold float64) (bool, error) {
	// Convert float64 to scaled integers to work with gnark's arithmetic circuits
	// Scale by 100 to handle 2 decimal places (e.g., 3.5 becomes 350)
	gpaScaled := int(gpa * 100)
	thresholdScaled := int(threshold * 100)

	// Create full witness assignment (includes private GPA)
	assignment := &GPAThresholdCircuit{
		Threshold: thresholdScaled,
		GPA:       gpaScaled,
	}

	// Create gnark witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return false, err
	}

	// Generate proof
	proof, err := groth16.Prove(p.ccs, p.pk, witness)
	if err != nil {
		// If proof generation fails, that means the condition wasn't met
		return false, nil
	}

	// Verify the proof with only public data
	publicWitness, err := witness.Public()
	if err != nil {
		return false, err
	}
	err = groth16.Verify(proof, p.vk, publicWitness)
	if err != nil {
		return false, nil
	}

	return true, nil
}
