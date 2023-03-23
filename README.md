# nsr
Network stack in rust

The goal of this project is to learn rust language, especially its system programming part and obtain deep knowledges about the network stack.

OSes, at least Linux/*nix and Windows, provide virtual interfaces *tun/tap* backed by user space programms rather than physical network devices. Thus network packets (IP/Ethernet) can be injected or retrived from OS's network stack from/to a user space program. So network packets can be constructed or analized in a user space program to emulate network stack.

As we have a full control of Ethernet packets it's possible to emulate a physical network with network devices such as switches and routers which is also a goal of this project.
