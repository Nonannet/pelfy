#Change to debian:stable-20250224⁠ if build fails
FROM debian:stable

WORKDIR /src

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc

RUN apt-get install -y \
    gcc-12-arm-linux-gnueabihf \
    gcc-12-mips-linux-gnu \
    gcc-12-riscv64-linux-gnu \
    gcc-12-aarch64-linux-gnu

RUN apt-get install -y \
    gcc-12-aarch64-linux-gnu

COPY * /src/

CMD bash make_objs.sh gcc -O0 && \
    bash make_objs.sh gcc -O3 && \
    bash make_objs.sh arm-linux-gnueabihf-gcc-12 -O0 && \
    bash make_objs.sh arm-linux-gnueabihf-gcc-12 -O3 && \
    bash make_objs.sh aarch64-linux-gnu-gcc-12 -O0 && \
    bash make_objs.sh aarch64-linux-gnu-gcc-12 -O3 && \
    bash make_objs.sh mips-linux-gnu-gcc-12 -O0 && \
    bash make_objs.sh mips-linux-gnu-gcc-12 -O3 && \
    bash make_objs.sh riscv64-linux-gnu-gcc-12 -O0 && \
    bash make_objs.sh riscv64-linux-gnu-gcc-12 -O3 && \
    bash make_objs.sh riscv64-linux-gnu-gcc-12 "-O0 -march=rv32imac -mabi=ilp32" && \
    bash make_objs.sh riscv64-linux-gnu-gcc-12 "-O3 -march=rv32imac -mabi=ilp32"
