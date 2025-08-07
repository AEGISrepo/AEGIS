# How to Get DWARF

> [Documentation - Debug Symbol Packages](https://documentation.ubuntu.com/server/reference/debugging/debug-symbol-packages/)



## Get From Distribution Repository

### Import the signing key

Import the debug symbol archive [signing key](https://help.ubuntu.com/community/Repositories/Ubuntu#Authentication_Tab) from the Ubuntu server. On Ubuntu 18.04 LTS and newer, run the following command:

```
sudo apt install ubuntu-dbgsym-keyring
```



### Create a ddebs.list file

Create an `/etc/apt/sources.list.d/ddebs.list` by running the following line at a terminal:

```
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list
```



You can also add these repositories in your software sources from the Ubuntu software center or from Synaptic (refer to [this article](https://help.ubuntu.com/community/Repositories/Ubuntu), especially the section on [adding other repositories](https://help.ubuntu.com/community/Repositories/Ubuntu#Adding_Other_Repositories)). You will need to add lines like:

```
deb http://ddebs.ubuntu.com focal main restricted universe multiverse
```



Make sure you replace “focal” with the Ubuntu release name you’re using.

### Update package list

Run the following to update your package list or click the Reload button if you used the Synaptic Package Manager:

```
sudo apt-get update
```



### Install the symbols package

```sh
sudo apt-get install linux-image-`uname -r`-dbgsym
```

#### Manual install of debug packages

To install the debug symbol package (`*-dbgsym.ddeb`) for a specific package, you can now invoke:

```
sudo apt-get install PACKAGE-dbgsym
```



For example, to install the debug symbols for `xserver-xorg-core`:

```
sudo apt-get install xserver-xorg-core-dbgsym
```



As mentioned in the section above, some packages will ship their debug symbols via `*-dbg.deb` packages instead. Using `glibc` as an example, you can install its debug symbols using:

```
sudo apt-get install libc6-dbg
```







- **Binary Debug Symbols:** `/usr/lib/debug/usr/bin/<binary_name>`
- **Library Debug Symbols:** `/usr/lib/debug/lib/<architecture>/<library_name>-<version>.so`
- **Shared Object Debug Symbols:** `/usr/lib/debug/usr/lib/<architecture>/<object_name>.so`

- **Kernel Image Debug Symbols:** `/usr/lib/debug/boot/vmlinux-<kernel_version>`
- **Kernel Module Debug Symbols:** `/usr/lib/debug/lib/modules/<kernel_version>/.../*.ko`



## Get From Compile time

By splitting the debug information into two parts at compile time -- one part that remains in the .o file and another part that is written to a parallel .dwo ("DWARF object") file -- we can reduce the total size of the object files processed by the linker.

Use the `-gsplit-dwarf` option to enable the generation of split DWARF at compile time. This option must be used in conjunction with `-c.`





## Get From tools like `llm4decompile`





