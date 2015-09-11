package main

import (
    "fmt"
    "log"
    "net/http"
    "io/ioutil"
    "bytes"
    "github.com/docopt/docopt-go"
    "golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/openpgp/clearsign"

)


// Image signing key: buildbot@coreos.com
var GPG_KEY_URL string = "https://coreos.com/security/image-signing-key/CoreOS_Image_Signing_Key.pem"
var GPG_LONG_ID string = "50E0885593D2DCB4"


func main() {
    usage := `
 
Usage:
    create-coreos-vdi [-V VERSION] [-p PATH]
    
Options:
    -d DEST     Create CoreOS VDI image to the given path.
    -V VERSION  Version to install (e.g. alpha) [default: stable]
    -h          This help

This tool creates a CoreOS VDI image to be used with VirtualBox.
`

    arguments, _ := docopt.Parse(usage, nil, true, "Coreos create-coreos-vdi 0.1", false)

    
    RAW_IMAGE_NAME := "coreos_production_image.bin"
    IMAGE_NAME := RAW_IMAGE_NAME + ".bz2"
    DIGESTS_NAME := IMAGE_NAME + ".DIGESTS.asc"
    
    VERSION_ID, _ := arguments["-V"].(string)
    
    var BASE_URL string
    
    switch VERSION_ID {    
        case "stable":
            BASE_URL = "http://stable.release.core-os.net/amd64-usr/current"
        case "alpha":
            BASE_URL = "http://alpha.release.core-os.net/amd64-usr/current"
        case "beta":
            BASE_URL = "http://beta.release.core-os.net/amd64-usr/current"
        default:
            BASE_URL = "http://storage.core-os.net/coreos/amd64-usr/" + VERSION_ID
    }
    
        
    IMAGE_URL := BASE_URL + "/" + IMAGE_NAME
    DIGESTS_URL := BASE_URL + "/" + DIGESTS_NAME
    //DOWN_IMAGE := WORKDIR + "/" + RAW_IMAGE_NAME
    
    //image_head_result, err := http.Head(IMAGE_URL)
    _, err := http.Head(IMAGE_URL)
    if err != nil {
        log.Fatal("Image URL unavailable:" + IMAGE_URL)
    }
    digests_get_result, err := http.Get(DIGESTS_URL)
    if err != nil {
        log.Fatal("Image signature unavailable:" + DIGESTS_URL)
    }
    digests_messagetext, err := ioutil.ReadAll(digests_get_result.Body)
    digests_get_result.Body.Close()

    pubkey_get_result, err := http.Get(GPG_KEY_URL)
    if err != nil {
        log.Fatal(err)
    }
    
    pubkey, _ := ioutil.ReadAll(pubkey_get_result.Body)
    pubkey_get_result.Body.Close()
    
    pubkey_buffer := bytes.NewBufferString(string(pubkey))
    keyring, err := openpgp.ReadArmoredKeyRing(pubkey_buffer)
    if err != nil {
        log.Fatal(err)
    }
	digests_clearsign_message, _ := clearsign.Decode(digests_messagetext)
    digests_clearsign_message_reader := bytes.NewReader(digests_clearsign_message.Bytes)

    res, err := openpgp.CheckDetachedSignature(keyring, digests_clearsign_message_reader, digests_clearsign_message.ArmoredSignature.Body)
    if res != nil {
       fmt.Println("Yay! Valid!")
    }

    vboxmanage, _ := get_vboxmanage()
    fmt.Print(vboxmanage)
}