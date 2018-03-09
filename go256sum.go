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
 
package main    


import (
    "fmt"
    "crypto"
    "flag"
    "encoding/hex"
    "go256sum/filehash"
    "go256sum/reffile"
    "go256sum/bsdref"    
    "os"
    "strings"
)

type GrapError struct {
    errorCode int
    errorFunc func() string
}

func (e GrapError) Error() string {
    return errorFunc()
}

const (
    ERR_GENERAL iota
    ERR_OK iota             //OK should not be an error
)

func resultMessage(fileName string, res bool) string {
    var result string
    
    if res {
        result = fmt.Sprintf("%s: OK", fileName)                
    } else {
        result = fmt.Sprintf("%s: FAILURE", fileName)                
    }
    
    return result
}

func cliVerifyOneFile(fileName, referenceValueHexStr string, hashAlgo crypto.Hash) error {
    referenceValue, err := hex.DecodeString(strings.TrimSpace(referenceValueHexStr))
    if err != nil {
        fmt.Printf("Unable to parse hash value: %v\n", err)
        return GrapErrorf(ERR_GENERAL)
    }
    
    refData := map[string][]byte {fileName: referenceValue}
    
    return verifyRefData(refData, hashAlgo)
}

func cliVerifyReferenceFile(refFileName string) error {   
    file, err := os.Open(refFileName)
    if err != nil {
        fmt.Printf("Unable to open reference file: %v\n", err)
        return GrapErrorf(ERR_GENERAL)
    }
    defer file.Close()        
    
    referenceData, detectedAlgo, err := reffile.AttemptParse(file)
    if err != nil {
        fmt.Printf("Unable to parse reference file: %v\n", err)
        return GrapErrorf(ERR_GENERAL)
    }
    
    return verifyRefData(referenceData, detectedAlgo)
}

func verifyRefData(refData map[string][]byte, hashAlgo crypto.Hash) error {
    var hashFailCount uint = 0
    
    outFunc := func (fName string, res bool) {
        if !res {
            hashFailCount++
        } 
        fmt.Println(resultMessage(fName, res))
    }

    if _, err := filehash.VerifyReferenceData(refData, hashAlgo, outFunc); err != nil {
        fmt.Println(err)
        return GrapErrorf(ERR_GENERAL)
    }
            
    if hashFailCount > 0 {
        fmt.Printf("There were %d FAILURES\n", hashFailCount)
        return GrapErrorf(ERR_GENERAL)
    }
    
    return GrapErrorf(ERR_OK)
}

func cliHashFiles(filesToHash []string) error {
    if err := reffile.Fill(os.Stdout, filesToHash); err != nil {
        fmt.Println(err)
        return GrapErrorf(ERR_GENERAL)
    }
    
    return GrapErrorf(ERR_OK)
}
 
func main() {
    var resCode int
    checkValPtr := flag.String("refval", "", "Reference value to check")
    checkFilePtr := flag.String("reffile", "", "Name of file containing reference values")    
    useSHA512Ptr := flag.Bool("use512", false, "Use SHA512 instead of SHA256 if present")
    useBSDPtr := flag.Bool("usebsd", false, "Use BSD format for output. More or less ignored for verification")
        
    flag.Parse()
    
    switch {
    case *useSHA512Ptr && *useBSDPtr:
        reffile.UseFormat(bsdref.BSDFormat512)
    case *useSHA512Ptr && !*useBSDPtr:
        reffile.UseFormat(reffile.DefaultFormat512)
    case !*useSHA512Ptr && *useBSDPtr:
        reffile.UseFormat(bsdref.BSDFormat)
    case !*useSHA512Ptr && !*useBSDPtr:
        reffile.UseFormat(reffile.DefaultFormat)
    }
        
    switch {
    case (*checkValPtr != "") && (len(flag.Args()) == 1) && (*checkFilePtr == ""):
        resCode = cliVerifyOneFile(flag.Args()[0], *checkValPtr, reffile.CurrentAlgo())
        
    case (*checkFilePtr != "") && (len(flag.Args()) == 0) && (*checkValPtr == ""):
        resCode = cliVerifyReferenceFile(*checkFilePtr)
        
    case (*checkValPtr == "") && (*checkFilePtr == "") && (len(flag.Args()) >= 1):
         resCode = cliHashFiles(flag.Args())
            
    default:
        flag.PrintDefaults()
        os.Exit(GrapErrorf(ERR_GENERAL).errorCode)
    }    
    
    os.Exit(resCode)
}

func GrapErrorf(errorCode int) {
    return GrapError {
        errorCode: errorCode,
        errorFunc: errorCodeTranslator(errorCode)
    }
}

func errorCodeTranslator(errorCode int) string {
    switch errorCode {
    case ERR_GENERAL:
        return "ERR_GENERAL"
    case ERR_OK:
        return "ERR_OK"
    }
    return "ERR_UNDEF"
  
}
