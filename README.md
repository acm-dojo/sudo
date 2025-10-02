# Sudo

Locked-down set-uid wrappers for running pre-approved root scripts in ACM Dojo challenges.

## Components

- `bash.c` / `bash`: verifies a target shell script against the signature list, then launches `/bin/bash` with the provided arguments.
- `python.c` / `python`: same flow, but executes `/run/dojo/bin/python` for signed Python scripts.
- `verify.h`: shared hardening utilities (path validation, whitelist check, environment scrubbing, resource limits).
- `setup.sh`: convenience script that assigns `root:root` ownership, sets the set-uid bit on the compiled wrappers, and provides the signature file at `/challenge/.signature`.

## Usage

Clone this repository into any dojo repo as a submodule, then add the module to the mounts hook in `dojo.yml`:

```
mounts:
  - id: sudo
```

If you wish to sign a file for execution, add it to the challenge's `.signature` file (one per line, use absolute path). Use `/mnt/sudo/bash` or `/mnt/sudo/python` as shebang in the corresponding scripts.

Always invoke `setup.sh` at the end of the `.init` file. This script configures the wrappers and also takes a snapshot of the current environment variables to be used by the sudo binaries. Any changes to environment variables after this script is run will not be reflected when using the sudo binaries.

## Development

After the bash or python source code is modified, please recompile the binaries with `dojo-g++` to ensure compatibility with the dojo environment. You can find this utility at [acm-dojo-tools](https://github.com/acm-dojo/acm-dojo-tools/).