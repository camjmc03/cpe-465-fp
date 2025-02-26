# ensure dependencies are installed
echo "Checking dependencies..."
# cmake
if ! [ -x "$(command -v cmake)" ]; then
    echo "Error: cmake is not installed." >&2
    exit 1
fi
# make
if ! [ -x "$(command -v make)" ]; then
    echo "Error: make is not installed." >&2
    exit 1
fi
# g++
if ! [ -x "$(command -v g++)" ]; then
    echo "Error: g++ is not installed." >&2
    exit 1
fi
# git
if ! [ -x "$(command -v git)" ]; then
    echo "Error: git is not installed." >&2
    exit 1
fi
# pcap
if ! [ -x "$(command -v pcap-config)" ]; then
    echo "Error: pcap is not installed." >&2
    exit 1
fi

# create build directory if it doesn't exist
if [ ! -d build ]; then
    mkdir build
fi
cd build
echo "Building..."
echo "Running cmake"
cmake ..
echo "Running make"
make -j$(sysctl -n hw.ncpu)
echo "Creating the run script"
cd ..
# make the run script and set it to be executable
if [ -f run.sh ]; then
    rm run.sh
fi
echo "#!/bin/bash" > run.sh
echo "./build/dns_server" >> run.sh
echo "cd .." >> run.sh
chmod +x run.sh
echo "---------------------------------------------"
echo "Build complete. Run the program with ./run.sh"
echo "---------------------------------------------"
