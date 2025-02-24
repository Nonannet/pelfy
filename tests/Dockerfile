# Start with a base image containing build tools and libraries
FROM ubuntu:latest as builder

# Set the working directory
WORKDIR /src

# Install necessary build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
#    g++ \
#    make \
#    wget \
#    curl \
#    git \
#    ca-certificates \
#    bison \
#    flex \
#    python3 \
#    texinfo

# Install cross-compilers for x86, ARM, MIPS, and RISC-V
RUN apt-get install -y \
    gcc-multilib \
    gcc-arm-linux-gnueabihf \
    gcc-mips-linux-gnu \
    gcc-riscv64-linux-gnu \
    gcc-aarch64-linux-gnu

# Copy the C file into the container
COPY test.c /src/

# Compile the C file for x86
RUN gcc -c -O0 -o obj/test-x86-o0.o test.c \
    gcc -c -03 -o obj/test-x86-o3.o test.c \
    # Compile the C file for ARM
    arm-linux-gnueabihf-gcc -c -O0 -o obj/test-arm-o0.o test.c \
    arm-linux-gnueabihf-gcc -c -O3 -o obj/test-arm-o3.o test.c \
    # Compile the C file for MIPS
    mips-linux-gnu-gcc -c -O0 -o obj/test-mips-o0.o test.c \
    mips-linux-gnu-gcc -c -O3 -o obj/test-mips-o3.o test.c \
    # Compile the C file for RISC-V
    riscv64-linux-gnu-gcc -c -O0 -o obj/test-riscv-o0.o test.c \
    riscv64-linux-gnu-gcc -c -03 -o obj/test-riscv-o3.o test.c

# Set the default command (just listing the files as an example)
CMD ["ls", "-l"]