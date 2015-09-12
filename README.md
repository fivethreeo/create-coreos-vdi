# create-coreos-vdi

Golang tools for dowloading/building virtualbox vdi

## Installation

Install golang

```
go get github.com/fivethreeo/create-coreos-vdi
go install github.com/fivethreeo/create-coreos-vdi
```

## Usage

Install virtualbox

```
create-coreos-vdi -h
create-coreos-vdi
```

To test the vdi with virtualbox

Make sure you have mkisofs installed in linux

```
go get github.com/fivethreeo/create-basic-configdrive
go install github.com/fivethreeo/create-basic-configdrive

create-basic-configdrive -H myhostname -S ~/.ssh/mykey.pub

VBoxManage clonehd coreos_production.vdi mymachine.vdi
VBoxManage modifyhd mymachine.vdi --resize 10240

VBoxManage createvm --name mymachine --register

VBoxManage modifyvm "mymachine" --memory 1024 --vram 128
VBoxManage modifyvm "mymachine" --nic1 bridged --bridgeadapter1 "adapter"
VBoxManage modifyvm "mymachine" --nic2 intnet --intnet2 intnet --nicpromisc2 allow-vms

VBoxManage storagectl "mymachine" --name "IDE Controller" --add ide
VBoxManage storageattach "mymachine" --storagectl "IDE Controller" \
  --port 0 --device 0 --type hdd --medium mymachine.vdi
VBoxManage storageattach "mymachine" --storagectl "IDE Controller" \
  --port 1 --device 0 --type dvddrive --medium myhostname.iso
```

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

Code working

## Credits

Øyvind Saltvik

## License

BSD MIT something
