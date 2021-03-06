package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/cheggaaa/pb"
	"github.com/docopt/docopt-go"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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

	_, _ = get_vboxmanage()

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

	dest, ok := arguments["-p"].(string)
	if ok == false {
		dest, _ = os.Getwd()
	}

	workdir, _ := ioutil.TempDir(dest, "coreos")
	defer os.RemoveAll(workdir)
	
	IMAGE_URL := fmt.Sprintf("%s/%s", BASE_URL, IMAGE_NAME)
	DIGESTS_URL := fmt.Sprintf("%s/%s", BASE_URL, DIGESTS_NAME)
	DOWN_IMAGE := filepath.Join(workdir, RAW_IMAGE_NAME)

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
	VDI_IMAGE := filepath.Join(dest, VDI_IMAGE_NAME)

	decoded_long_id, err := hex.DecodeString(GPG_LONG_ID)
	decoded_long_id_int := binary.BigEndian.Uint64(decoded_long_id)

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
	} else {
		if res.PrimaryKey.KeyId == decoded_long_id_int {
			fmt.Printf("Trusted key id %d matches keyid %d\n", decoded_long_id_int, decoded_long_id_int)
		}
		fmt.Printf("DIGESTS signature is valid: ")
	}

	var re = regexp.MustCompile(`(?m)(?P<method>(SHA1|SHA512)) HASH(?:\r?)\n(?P<hash>.[^\s]*)\s*(?P<file>[\w\d_\.]*)`)

	var keymap map[string]int = make(map[string]int)
	for index, name := range re.SubexpNames() {
		keymap[name] = index
	}

	matches := re.FindAllStringSubmatch(digests_text, -1)

	var bz_hash_sha1 string
	var bz_hash_sha512 string

	for _, match := range matches {
		if match[keymap["file"]] == IMAGE_NAME {
			if match[keymap["method"]] == "SHA1" {
				bz_hash_sha1 = match[keymap["hash"]]
			}
			if match[keymap["method"]] == "SHA512" {
				bz_hash_sha512 = match[keymap["hash"]]
			}
		}
	}

	sha1h := sha1.New()
	sha512h := sha512.New()

	fmt.Printf("downloading %s\n", IMAGE_NAME)

	response, err := http.Get(IMAGE_URL)
	defer response.Body.Close()

	bar := pb.New(int(response.ContentLength)).SetUnits(pb.U_BYTES)
	bar.Start()

	bzipped, _ := os.Create(filepath.Join(workdir, IMAGE_NAME))

	// create multi writer
	writer := io.MultiWriter(sha1h, sha512h, bar, bzipped)

	// and copy
	io.Copy(writer, response.Body)

	bar.FinishPrint("")

	bzipped.Close()

	if hex.EncodeToString(sha1h.Sum([]byte{})) == bz_hash_sha1 {
		fmt.Printf("SHA1 hash for %s match the one from DIGESTS\n", IMAGE_NAME)
	}
	if hex.EncodeToString(sha512h.Sum([]byte{})) == bz_hash_sha512 {
		fmt.Printf("SHA512 hash for %s match the one from DIGESTS\n", IMAGE_NAME)
	}

	fmt.Printf("Writing %s to %s...\n", IMAGE_NAME, RAW_IMAGE_NAME)

	bzip2_file, err := os.Open(filepath.Join(workdir, IMAGE_NAME))
	if err != nil {
		log.Fatal(err)
	}
	bzip2_reader := bzip2.NewReader(bzip2_file)

	bin_file, err := os.Create(DOWN_IMAGE)
	if err != nil {
		log.Fatal(err)
	}

	io.Copy(bin_file, bzip2_reader)
	bin_file.Close()

	cmd := exec.Command("vboxmanage", "convertdd", DOWN_IMAGE, VDI_IMAGE, "--format", "VDI")

	if runtime.GOOS == "windows" {
		// Use cmd /C on windows because LookPath is being difficult
		cmd = exec.Command("cmd", "/C", "vboxmanage", "convertdd", DOWN_IMAGE, VDI_IMAGE, "--format", "VDI")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Converting %s to VirtualBox format...\n", RAW_IMAGE_NAME)
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Success! CoreOS %s VDI image was created on %s.", VERSION_ID, VDI_IMAGE_NAME)
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
