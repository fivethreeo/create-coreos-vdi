package main

import (
	"fmt"
	"strings"
	"bufio"
	"bytes"
	"log"
	"os"
	"io"
	"io/ioutil"
	"net/http"
	"encoding/hex"
	"encoding/binary"
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
		BASE_URL = fmt.Sprintf("http://storage.core-os.net/coreos/amd64-usr/%s", VERSION_ID)
	}

	IMAGE_URL := fmt.Sprintf("%s/%s", BASE_URL, IMAGE_NAME)
	DIGESTS_URL := fmt.Sprintf("%s/%s", BASE_URL, DIGESTS_NAME)
	//DOWN_IMAGE := fmt.Sprintf("%s/%s", WORKDIR, RAW_IMAGE_NAME)

    dest, ok := arguments["-p"].(string)
    if ok == false {
        dest, _ = os.Getwd()
    }
    
	var err error

	_, err = http.Head(IMAGE_URL)
	if err != nil {
		log.Fatal("Image URL unavailable:" + IMAGE_URL)
	}

	digests_get_result, err := http.Get(DIGESTS_URL)
	if err != nil {
		log.Fatal("Image signature unavailable:" + DIGESTS_URL)
	}

	digests_raw_message, err := ioutil.ReadAll(digests_get_result.Body)
	digests_get_result.Body.Close()

	// Gets CoreOS verion from version.txt file
	VERSION_NAME := "version.txt"
	VERSION_URL := fmt.Sprintf("%s/%s", BASE_URL, VERSION_NAME)

	version_result, err := http.Get(VERSION_URL)
	vars, _ := ReadVars(version_result.Body)
	VDI_IMAGE_NAME := fmt.Sprintf("coreos_production_%s.%s.%s.vdi", vars["COREOS_BUILD"], vars["COREOS_BRANCH"], vars["COREOS_PATCH"])
	VDI_IMAGE := fmt.Sprintf("%s/%s", dest, VDI_IMAGE_NAME)

    decoded_long_id, err := hex.DecodeString(GPG_LONG_ID) 
    decoded_long_id_int :=  binary.BigEndian.Uint64(decoded_long_id)

	fmt.Printf("Trusted hex key id %s is decimal %d\n", GPG_LONG_ID, decoded_long_id_int)

	pubkey_get_result, err := http.Get(GPG_KEY_URL)
	if err != nil {
		log.Fatal(err)
	}

	pubkey, _ := ioutil.ReadAll(pubkey_get_result.Body)
	pubkey_get_result.Body.Close()

	pubkey_reader := bytes.NewReader(pubkey)
	keyring, err := openpgp.ReadArmoredKeyRing(pubkey_reader)
	if err != nil {
		log.Fatal(err)
	}

	decoded_message, _ := clearsign.Decode(digests_raw_message)
	digests_text := string(decoded_message.Bytes)
	decoded_message_reader := bytes.NewReader(decoded_message.Bytes)

	res, err := openpgp.CheckDetachedSignature(keyring, decoded_message_reader, decoded_message.ArmoredSignature.Body)
	if err != nil {
		fmt.Println("Signature check for DIGESTS failed.")
	}
	if res.PrimaryKey.KeyId == decoded_long_id_int {
	   fmt.Printf("Trusted key id %d mathes keyid %d\n", decoded_long_id_int, decoded_long_id_int)
	} 
	_ = fmt.Sprintf("%s %s", digests_text, VDI_IMAGE)

	vboxmanage, _ := get_vboxmanage()
	fmt.Print(vboxmanage)
}

func ReadVars(regular_reader io.Reader) (map[string]string, error) {
	config := make(map[string]string)
	reader := bufio.NewReader(regular_reader)
	for {
		line, err := reader.ReadString('\n')

		// check if the line has = sign
		// and process the line. Ignore the rest.
		if equal := strings.Index(line, "="); equal >= 0 {
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
				// assign the config map
				config[key] = value
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}
