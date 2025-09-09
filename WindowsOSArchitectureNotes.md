# 🪟 Key Components of Windows OS Architecture

| Component | Description |
|-----------|-------------|
| **Object Manager** | Central manager that handles all kernel objects (processes, threads, files, events, registry keys, etc.) and enforces handle-based access. |
| **Process Manager** | Manages process creation, termination, and scheduling of threads. Handles virtual address space for each process. |
| **Memory Manager** | Controls physical and virtual memory, paging, caching, and address translation. Implements demand paging and copy-on-write. |
| **I/O Manager** | Provides a uniform I/O system for devices, files, and network. Works with device drivers through IRPs (I/O Request Packets). |
| **Security Reference Monitor (SRM)** | Enforces security policies, including user permissions, tokens, and access checks on objects. |
| **Local Procedure Call (LPC) / Advanced LPC (ALPC)** | Provides inter-process communication (IPC) within the same system, used by user mode ↔ kernel mode interactions. |
| **Plug and Play (PnP) Manager** | Detects and configures hardware devices, loads device drivers dynamically. |
| **Power Manager** | Manages system power states, device power states, and power-saving features (sleep, hibernate, ACPI support). |
| **Configuration Manager** | Manages the Windows Registry, storing system and application configuration data. |
| **Cache Manager** | Provides system-wide file caching for improved file I/O performance. |
| **Executive (Windows Executive)** | A set of kernel-mode services (includes most of the components above) that sit above the kernel and below user mode. |
| **Kernel** | Low-level core responsible for thread scheduling, interrupts, exceptions, and synchronization primitives. |
| **Hardware Abstraction Layer (HAL)** | Abstracts hardware details (interrupts, I/O ports, multiprocessor support) so Windows can run on diverse hardware platforms. |
| **Win32 Subsystem** | The main user-mode subsystem providing the Windows API for applications (GUI, console, user input). |
| **CSRSS (Client/Server Runtime Subsystem)** | Handles console windows, process/thread creation in user mode, and parts of the Win32 API. |
| **SMSS (Session Manager Subsystem)** | First user-mode process, responsible for launching subsystems, environment variables, and session creation. |
| **LSASS (Local Security Authority Subsystem Service)** | Manages authentication, logon, and local security policies. |
| **Services Control Manager (SCM)** | Starts, stops, and manages Windows services. |
| **Winlogon** | Handles user logon, logoff, and secure attention sequence (Ctrl+Alt+Del). |

