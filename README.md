# tsn_monitor Kernel Module

This guide explains how to compile, insert, and use the Netstats kernel module to check network statistics.

## Steps

1. **Compiling the Module**  
   ```bash
   make
2. **Insert the module into the kernel**
   ```bash
   sudo insmod tsn_monitor.ko
3. **Check the network statistics**
   ```bash
   cat /proc/tsn_monitor
4. **Unload the module**
   ```bash
   sudo rmmod tsn_monitor
5. **Clean up the compiled files**
   ```bash
   make clean
