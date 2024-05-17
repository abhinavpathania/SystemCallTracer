## System Call Tracer

This project implements a system call tracer for Unix-based systems (Linux, macOS). It allows you to monitor and track the system calls made by a target program.

**Features:**

* Attaches to a child process created using `fork`.
* Traces system calls made by the child process.
* Provides human-readable names for known system calls (optional, requires a system call mapping).
* Allows identification of unknown system calls by their numeric values.

**Installation:**

1. **Prerequisites:**
    * A C compiler (e.g., GCC) installed on your system.
    * Basic understanding of Unix system calls and process management.

2. **Compilation:**

    ```bash
    gcc system_call_tracer.c -o system_call_tracer  
    ```

**Usage:**

1. **Run the tracer:**

    ```bash
    ./system_call_tracer <target_program>  # Replace '<target_program>' with the program to trace
    ```

2. **Output:**

    The program will print information about the traced system calls, including their names (if available) or numeric values.


**Author:**



**CAUTION:**

* This is a basic system call tracer for educational purposes.
* Be cautious when using tracers, especially on untrusted programs.
* Consider implementing more robust error handling and user input validation in future improvements.
