package authentication

import (
    "crypto/rand"
    "fmt"
    "math/big"
)

func GenerateOTP(length int) (string, error) {
    otp := ""
    for i := 0; i < length; i++ {
        n, err := rand.Int(rand.Reader, big.NewInt(10))
        if err != nil {
            return "", err
        }
        otp += fmt.Sprintf("%d", n.Int64())
    }
    return otp, nil
}
