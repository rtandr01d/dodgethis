import subprocess


def dump(path):
    command = [
        "llvm-objdump-15", 
        "-d", 
        path
    ]

    try:
        # Run the command and capture the standard output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing objdump: {e.stderr}")
        return None

def get_asm(asm, syscall):
  for line in asm:
    if(syscall in line):
      print(line)
