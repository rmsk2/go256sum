/***************************************************************************
 * Copyright 2018 Martin Grap
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ***************************************************************************/

package filehash

import (
    "fmt"
    "crypto"
    _ "crypto/sha256"
    _ "crypto/sha512"
    "io"
    "os"
    "bytes"
)

type PrintFunc func(string, bool)
type OutFunc func(string, []byte, crypto.Hash)

func Verify(fileName string, referenceHash []byte, hashAlgo crypto.Hash) (bool, error) {
    hash, err := Calc(fileName, hashAlgo)
    
    if err != nil {
        return false, fmt.Errorf("Unable to verify hash: %v", err)
    }
    
    return bytes.Compare(hash, referenceHash) == 0, nil
}

func Calc(fileName string, hashAlgo crypto.Hash) ([]byte, error) {
    var hashVal []byte
    
    hasher := hashAlgo.New()
    
    file, err := os.Open(fileName)
    if err != nil {
        return nil, fmt.Errorf("Unable to open input file: %v", err)
    }
    defer file.Close()    

    if _, err := io.Copy(hasher, file); err != nil {
        return nil, fmt.Errorf("Unable to hash data: %v", err)
    }
        
    return hasher.Sum(hashVal), nil
}

func CalcReferenceData(fileNames []string, hashAlgo crypto.Hash, outCallback OutFunc) (map[string][]byte, error) {
    result := make(map[string][]byte)
    var hashVal []byte
    var err error

    for _, fileName := range fileNames {
        if hashVal, err = Calc(fileName, hashAlgo); err != nil {
            return nil, err
        }
        
        result[fileName] = hashVal

        if outCallback != nil {
            outCallback(fileName, hashVal, hashAlgo)
        }
    }

    return result, nil
}

func VerifyReferenceData(referenceData map[string][]byte, hashAlgo crypto.Hash, printCallback PrintFunc) (map[string]bool, error) {
    result := make(map[string]bool)
    
    for file, hashVal := range referenceData {
        verificationResult, err := Verify(file, hashVal, hashAlgo)
        if err != nil {
            return nil, fmt.Errorf("Unable to verify hash: %v", err)
        }
        
        if printCallback != nil {
            printCallback(file, verificationResult)
        }
        
        result[file] = verificationResult
    } 
    
    return result, nil
}
