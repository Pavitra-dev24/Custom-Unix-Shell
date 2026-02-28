# Custom-Unix-Shell

A lightweight Unix-style shell written in C that demonstrates core OS concepts: process control, job management, and basic file operations. Includes **15+ built-in commands**, background jobs, command history, and simple job control using low-level system calls.

---

## Features

- Interactive shell with custom prompt
- 15+ built-in commands:
  - cd, pwd, ls
  - mkdir, rmdir
  - touch, rm, cp, mv
  - cat, echo
  - history, clear
  - which, jobs, fg, bg
  - help, exit
- Background process execution using `&`
- Job tracking and control
- Command history (in-memory)
- File creation, deletion, copying, and navigation
- Uses low-level Linux system calls:
  - fork()
  - execvp()
  - waitpid()
  - open(), read(), write()
  - mkdir(), rmdir(), unlink()

---

## Implementation Details

The shell is built using low-level POSIX system calls and follows a modular design to handle command execution, job management, and filesystem operations.

Core implementation includes:

- **Command Execution**
  - Uses `fork()` to create child processes
  - Executes programs using `execvp()`
  - Foreground processes handled using `waitpid()`

- **Background Jobs**
  - Supports execution using `&`
  - Tracks jobs using a custom job list
  - Provides job control using `jobs`, `fg`, and `bg`

- **Signal Handling**
  - Uses `SIGCHLD` to detect completed background processes
  - Prevents zombie processes by reaping children

- **File Operations**
  - Implements commands like:
    - `touch`, `rm`, `cp`, `mv`, `mkdir`, `rmdir`
  - Uses system calls like:
    - `open()`, `read()`, `write()`, `unlink()`, `rename()`

- **Command Parsing**
  - Tokenizes user input
  - Supports quoted strings
  - Detects background execution

---

## Files in Repository

- `shell.c` → Main source code of the custom shell  
- `README.md` → Project documentation  

---

## Concepts Covered

- Process creation & execution  
- Signal handling (`SIGCHLD`)  
- Job control  
- File system operations  
- Command parsing & tokenization  

---

## Limitations

This is a basic educational shell and does not support:

- Pipes (`|`)  
- Input/output redirection (`>`, `<`)  
- Advanced scripting  

---

## Purpose

Built as a Systems Programming project to understand how Unix shells manage:

- Processes  
- Files  
- Commands  
- Background execution  

---
