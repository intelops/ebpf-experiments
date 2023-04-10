> # Environment
> - OS: `Linux`
> - Linux Distros: `Ubuntu 22.04`
> - kernel version: `5.19.0-38-generic`
> - Arch: `x86_64`

> # Dependencies
> - make
> ```
> sudo apt install make
> ```
> Once make was installed, all other dependencies can be installed using `make install`
> - go
>   - version: 1.18.1
> ```bash
> sudo apt install golang
> ```
> - Clang and LLVM
>   - version: 14.0.0.1ubuntu1
> ```bash
> sudo apt install clang llvm
> ```
> - libelf-dev
> ```
> sudo apt install libelf-dev
> ```
> - Linux Tools - bpftool
> ```
> sudo apt install linux-tools-$(uname -r)
> ```

> # Dependencies installation
> ```
> make install
> ````
> This will install all the required dependencies.

> # Build
> ```
> make build
> ````
> Make use of this command to rebuild the programs.  
> Executable is saved to `exec/` folder.

> # Headers
> ```
> make headers
> ```
> This will regenerate all the headers in headers directory. In order to make this command work correctly you might need to install bpftools, libelf, linux tools. 

> # Run
> ```
> make run
> ```
> Executes the ebpf execve programs. Captures the all `execve entry sycalls` and prints it to console.

> # Clean
> ```
> make clean
> ```
> Deletes all generated files.

> # Sample Output
> ![output](./sample_output.png)