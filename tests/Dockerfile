# Start with a base image containing build tools and libraries
FROM debian:stable

# Set the working directory
WORKDIR /src

# Install necessary build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc
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
    gcc-12-arm-linux-gnueabihf \
    gcc-12-mips-linux-gnu \
    gcc-12-riscv64-linux-gnu \
    gcc-12-aarch64-linux-gnu

# Copy the C file into the container
COPY test.c /src/

# Compile the C file for x86
CMD gcc -c -O0 test.c -o ../obj/test-x86-o0.o && \
    gcc -c -O3 test.c -o ../obj/test-x86-o3.o && \
    # Compile the C file for ARM
    arm-linux-gnueabihf-gcc-12 -c -O0 test.c -o ../obj/test-arm-o0.o && \
    arm-linux-gnueabihf-gcc-12 -c -O3 test.c -o ../obj/test-arm-o3.o && \
    # Compile the C file for MIPS
    mips-linux-gnu-gcc-12 -c -O0 test.c -o ../obj/test-mips-o0.o && \
    mips-linux-gnu-gcc-12 -c -O3 test.c -o ../obj/test-mips-o3.o && \
    # Compile the C file for RISC-V
    riscv64-linux-gnu-gcc-12 -c -O0 test.c -o ../obj/test-riscv-o0.o && \
    riscv64-linux-gnu-gcc-12 -c -O3 test.c -o ../obj/test-riscv-o3.o
