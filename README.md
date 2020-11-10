# ESP32-QEMU-FUZZ
A Fuzzing Framework for ESP32 applications

# Prerequisites
Does not work on WSL!
Needs all prerequisites for honggfuzz, qemu and esp-idf!


# Setup


* Build Honggfuzz (make)

* Configure QEMU
<code>
./configure --target-list=xtensa-softmmu 
    --enable-debug 
    --disable-strip --disable-user 
    --disable-capstone --disable-vnc 
    --disable-sdl --disable-gtk 
    --honggfuzz-path="$(pwd)/../honggfuzz/"
</code>

* Build QEMU (make)


# Building Example Server Application

* For building example applications install ESP-IDF according to https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/linux-setup.html 

* Run **idf.py menuconfig** to configure app. Connection must be set to OpenCores Ethernet for networking within QEMU. Stack Protection and Heap Protection should be turned on and RTOS should be set to run on one core only for successful fuzzing. 

* Run **idf.py build** to build app

* Run **./make-flash-img.sh tcp_server tcp_server.img** to create flash image for QEMU 



# Whitebox Fuzzing within QEMU

<code>
./honggfuzz/honggfuzz -f ./example_esp32_server/in --save_all --thread 1 --max_file_size 127 -- 
./qemu/xtensa-softmmu/qemu-system-xtensa 
 -nographic -machine esp32 
 -drive file=./example_esp32_server/tcp_server.img,if=mtd,format=raw 
 -global driver=timer.esp32.timg,property=wdt_disable,value=true 
 -nic user,model=open_eth,hostfwd=tcp::8081-:80 
</code>

The coverage data can be very noisy, because the coverage of the whole system is respected. To isolate the coverage of specific functions, the first have to be roughly located within the address space for example by executing:
<code> readelf ./example_esp32_server/build/tcp_server.elf -s | grep processData </code>

The address space, that should be considered can be limited by changing the variables **hfuzz_qemu_start_code** and **hfuzz_qemu_start_code** in the file <code> ./qemu/hw/xtensa/esp32.c </code>
For the example application, setting the considered address space to 0x400d5000 - 0x400d5f00 speeds up the fuzzing process incredibly. A fault should then be found within minutes. 

# Blackbox Fuzzing within QEMU 


First, a setup-point has to be found. This is an address, that is reached, when the initializing of all os functions is finished. For example, the beginning of the function **app_main** which can be found by executing <code> readelf ./example_esp32_server/build/tcp_server.elf -s | grep app_main </code>

Next an entry point and multiple exit points need to be defined. The binary of an esp32 firmware image can be examined with radare2. If the ELF file is available, this can be done by <code> r2 -a xtensa tcp_server.elf</code>


In this example, the entry point is set to 0x400d5278 because it is the first instruction of the function **processData**. 
As exit point, the address right after the call to the **processData** function within the function **do_retransmit** is used: 0x400d53f0

Now, the state of the device, when reaching the entry address has to be dumped. Therefore, the device is connected to the debugger gdb and a breakpoint is set to the entry point by executing <code> br *0x400d5278 </code>. 
When the breakpoint has it, the output of the command <code> info registers </code> is copied to a text file and the command <code> dump binary memory dump.bin 0x3FF80000 0x3FFFFFFF </code> is executed to dump the whole RAM. 

Finally, the registers which hold the pointer and the length of the input data must be examined. Mostly, the can be discovered by reading the register dump file. In this case, register a10 is the length register and the value of register a11, 0x3ffbc43c, is the pointer to the input data. 

Now, the fuzzing can be started by the command

<code>
./honggfuzz/honggfuzz -f ./example_esp32_server/in --save_all --max_file_size 127 -- 
./qemu/xtensa-softmmu/qemu-system-xtensa 
 -nographic -machine esp32 
 -drive file=./example_esp32_server/tcp_server.img,if=mtd,format=raw 
 -global driver=timer.esp32.timg,property=wdt_disable,value=true 
 -fuzz setup=0x400d560c,entry=0x400d5278,exit=0x400d53f0,len=a10,data=0x3ffbc43c,dump_file=./example_esp32_server/dump.bin,regs_file=./example_esp32_server/regs_dump.txt
</code>

Multiple exit points can be defined by separating them with '+' For example <code> exit=0x400d53f0+0x400d5890 </code> 


# Whitebox Fuzzing via JTAG on Hardware

For performing coverage guided fuzzing on the device itself, the code coverage instrumentation from GCC is used. Therefore, each desired source file needs to be compiled with the flag <code> --coverage </code>, as described in https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/app_trace.html#app-trace-gcov-source-code-coverage .
The generated coverage data gets dumped by the provided fuzzing-hook and translated to the honggfuzz instance. Therefore, the fuzzing-hook needs to be modified to the actual target.  

# Credits

* https://github.com/google/honggfuzz
* https://github.com/thebabush/honggfuzz-qemu
* https://github.com/espressif/qemu
* https://hackernoon.com/afl-unicorn-part-2-fuzzing-the-unfuzzable-bea8de3540a5



