// +build !windows

package main

import (
    "fmt"
    "os"
    "os/exec"
)

func get_vboxmanage() (string, error) {
    vboxmanage, err := exec.LookPath("VBoxManage")
    if err != nil {
        fmt.Println("VBoxManage tool is required to create vdi.")
        os.Exit(1)
    }
    return vboxmanage, err
}