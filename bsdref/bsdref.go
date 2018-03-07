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

package bsdref

import (
    "fmt"
    "crypto"
    "encoding/hex"
    "regexp"
    "go256sum/reffile"
)

type bsdForm struct{
    hAlgo crypto.Hash
}

const BSDFormat = "bsd"
const BSDFormat512 = "bsd512"

var hashAlgos map[crypto.Hash]string

func init() {
    hashAlgos = map[crypto.Hash]string { 
        crypto.SHA256:"SHA256",
        crypto.SHA512:"SHA512",
    }
    
    reffile.RegisterFormat(BSDFormat, bsdForm{crypto.SHA256})
    reffile.RegisterFormat(BSDFormat512, bsdForm{crypto.SHA512})
}

func (this bsdForm) FormatLine(fileName string, hashVal []byte) string {
    var hashName string
    var ok bool
    
    if hashName, ok = hashAlgos[this.HashAlgo()]; !ok {
        panic("Unknown Hash function")
    }
    
    return fmt.Sprintf("%s (%s) = %x\n", hashName, fileName, hashVal)
}

func (this bsdForm) HashAlgo() crypto.Hash {
    return this.hAlgo
}

func (this bsdForm) ParseLine(lineToParse string) (string, []byte, error) {
    var hashName string
    var ok bool
    if hashName, ok = hashAlgos[this.HashAlgo()]; !ok {
        panic("Unknown hash algorithm")
    }

    regExpStr := fmt.Sprintf("^%s \\(([[:print:]]+)\\) = ([0123456789ABCDEFabcdef]{%d})$", hashName, 2 * this.HashAlgo().Size())
    regExp := regexp.MustCompile(regExpStr)
    var err error
    var referenceValue []byte

    matches := regExp.FindStringSubmatch(lineToParse)
    
    if matches == nil {
        return "", nil, fmt.Errorf("Unable to parse reference file line '%s'", lineToParse)
    }
    
    referenceValue, err = hex.DecodeString(matches[2])
    if err != nil {
        return "", nil, fmt.Errorf("Unable to parse reference file line '%s': %v", lineToParse, err)
    }
    
    return matches[1], referenceValue, nil
}

