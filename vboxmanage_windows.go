// +build windows

package main

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
)

func get_vboxmanage() (string, error) {
	vboxmanage, err := exec.LookPath("VBoxManage.exe")
	if err != nil {
		VboxKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Oracle\VirtualBox\`, registry.QUERY_VALUE)
		if err == nil {
			VboxInstallDir, _, err := VboxKey.GetStringValue("InstallDir")
			if err == nil {
        		fmt.Printf("set PATH=%s;%s\n", `%PATH%`, VboxInstallDir)
			}
		}
	}
	if err != nil {
		fmt.Println("VBoxManage tool is required to create vdi.")
		os.Exit(1)
	}
	return vboxmanage, err
}
