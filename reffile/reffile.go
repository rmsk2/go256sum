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

package reffile

import (
    "fmt"
    "crypto"
    "io"
    "bufio"
    "encoding/hex"
    "regexp"
    "go256sum/filehash"
)

const DefaultFormat = "default"
const DefaultFormat512 = "default512"

type FormatterParser interface {
    FormatLine(string, []byte) string
    ParseLine(string) (string, []byte, error)
    HashAlgo() crypto.Hash
}

type defaultForm struct{
    hAlgo crypto.Hash
}

var (
    current FormatterParser
    registry map[string]FormatterParser
)

func init() {
    registry = make(map[string]FormatterParser)
    RegisterFormat(DefaultFormat, defaultForm{crypto.SHA256})
    RegisterFormat(DefaultFormat512, defaultForm{crypto.SHA512})
    UseFormat(DefaultFormat)
}

func RegisterFormat(name string, fp FormatterParser) {
    registry[name] = fp
}

func UseFormat(name string) {
    var ok bool
    if current, ok = registry[name]; !ok {
        panic("Unknown Format")
    }
}

func KnownFormats() []string {
    result := []string{}
    
    for k, _ := range registry {
        result = append(result, k)
    }
    
    return result
}

func CurrentAlgo() crypto.Hash {
    return current.HashAlgo()
}

func AttemptParse(file io.ReadSeeker) (map[string][]byte, crypto.Hash, error) {
    var refFileContents map[string][]byte

    currentFormatter := current
    defer func() { current = currentFormatter }()

    var err error    
    var detectedAlgo crypto.Hash
    
    for k, _ := range registry {
        UseFormat(k)
        
        if _, err = file.Seek(0, io.SeekStart); err != nil {
            return nil, crypto.SHA256, fmt.Errorf("Unable to read reference file: %v", err)
        }
        
        refFileContents, err = parse(file)
        if err != nil {
            continue
        }
        
        detectedAlgo = current.HashAlgo()
        
        break
    }
    
    if err != nil {
        return nil, crypto.SHA256, fmt.Errorf("Unable to parse reference file: %v", err)
    }
    
    return refFileContents, detectedAlgo, nil
}

func Fill(file io.Writer, filesToHash []string) error {
    var out filehash.OutFunc = func (fileName string, hash []byte, algo crypto.Hash) {
        fmt.Fprint(file, current.FormatLine(fileName, hash))
    }

    _, err := filehash.CalcReferenceData(filesToHash, current.HashAlgo(), out)
    
    return err 
}

func parse(file io.ReadSeeker) (map[string][]byte, error) {
    result := make(map[string][]byte)
    var err error
    
    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        line := scanner.Text()
        
        fileName, hashVal, err := current.ParseLine(line)
        if err != nil {
            return nil, err
        }
 
        result[fileName] = hashVal
    }

    if err = scanner.Err(); err != nil {
        return nil, fmt.Errorf("Unable to read reference file: %v", err)
    }
    
    return result, nil    
}

func (this defaultForm) FormatLine(fileName string, hashVal []byte) string {
    return fmt.Sprintf("%x *%s\n", hashVal, fileName)
}

func (this defaultForm) HashAlgo() crypto.Hash {
    return this.hAlgo
}

func (this defaultForm) ParseLine(lineToParse string) (string, []byte, error) {
    regExpStr := fmt.Sprintf("^([0123456789ABCDEFabcdef]{%d}) \\*([^*]+)$", 2 * this.HashAlgo().Size())
    regExp := regexp.MustCompile(regExpStr)
    var err error
    var referenceValue []byte

    matches := regExp.FindStringSubmatch(lineToParse)
    
    if matches == nil {
        return "", nil, fmt.Errorf("Unable to parse reference file line '%s'", lineToParse)
    }
    
    referenceValue, err = hex.DecodeString(matches[1])
    if err != nil {
        return "", nil, fmt.Errorf("Unable to parse reference file line '%s': %v", lineToParse, err)
    }
    
    return matches[2], referenceValue, nil
}

