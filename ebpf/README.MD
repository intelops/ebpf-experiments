> # Development Environment
> - OS: `Linux`
> - Linux Distros: `Ubuntu 22.04`
> - kernel version: `5.19.0-38-generic`
> - Arch: `x86_64`

> # Dependencies
> ```
> make install
> ````
> This command installs all the required dependencies needed for this project to function properly.
> ```
> make uninstall
> ````
> This command removes all installed dependencies, effectively uninstalling them from the system.

> # Run
> ```
> make run
> ```
> This will start the execution of the application.

> # Build
> ```
> make build
> ````
> The project will be rebuilt, and the resulting executable file will be saved to a folder named `bin/`.

> # Headers
> ```
> make headers
> ```
> This will delete any existing header files and then generate fresh copies of all the header files.

> # Config
> ```
> make restore_default
> ```
> This will restore the configuration to its original default settings.

> # Clean
> ```bash
> make clean
> ```
> Deletes all generated files.
>
> ```bash
> make clean_obj
> ```
> This command will remove all object files located in the current directory, as well as delete any executable files located in the `bin` folder.
