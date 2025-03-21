Cameron McClure-Coleman

Advanced Networks (CPE 465)

Final Project

Custom DNS Server

This package is intended to be deployed on a raspberry pi running raspbian server. I have also 
gotten it to work on my MacBook.

This is a basic implementation of a DNS server that caches DNS queries and passes unknown queries along to an upstream DNS server set in the config file (8.8.8.8 by default)
Instructions for building and running the server:

1. Ensure you have CMake installed on your system. You can download it from https://cmake.org/download/.

2. Clone the repository
    ```sh
    git clone https://github.com/camjmc03/cpe-465-fp.git
    ```

3. run the build script
    ```sh
    ./build.sh
    ```
4. set settings in the config.yaml file
    - make sure the IP matches the IP for the interface you wish to serve DNS requests on. 
    - level 1 debug: packet recieved or sent
    - level 2 debug: internal logic
    - level 3 debug: packet hexdumps and parser results
5. Run the runner script 
    ```sh
    ../run.sh
    ```