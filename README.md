# esp32-fuzzing-framework
A Fuzzing Framework for ESP32 applications

#Prerequisites
Does not work on WSL!


#Setup


* Build Honggfuzz (make)

* Configure QEMU
<code>
./configure --target-list=xtensa-softmmu \
    --enable-debug \
    --disable-strip --disable-user \
    --disable-capstone --disable-vnc \
    --disable-sdl --disable-gtk \
    --honggfuzz-path="$(pwd)/../honggfuzz/"
    
</code>

* Build QEMU (make)


#Building Example Server Application

* For building example applications install ESP-IDF according to https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/linux-setup.html 

* Run **idf.py menuconfig** to configure app. Connection must be set to OpenCores Ethernet for networking within QEMU. Stack Protection and Heap Protection should be turned on and RTOS should be set to run on one core only for successful fuzzing. 

* Run **idf.py build** to build app

* Run **./make-flash-img.sh tcp_server tcp_server.img** to create flash image for QEMU 



#Run Whitebox Fuzzing

<code>
./honggfuzz/honggfuzz -f in --save_all --thread 1 --max_file_size 500 -- \
 ./qemu/xtensa-softmmu/qemu-system-xtensa \
 -nographic -machine esp32 \
 -drive \
 file=./example_esp32_server/tcp_server.img,if=mtd,format=raw \
 -global driver=timer.esp32.timg,property=wdt_disable,value=true \
 -nic user,model=open_eth,hostfwd=tcp::8081-:80 
</code>
