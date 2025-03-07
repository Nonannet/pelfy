#!/bin/bash

# Check if correct number of arguments is provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <compiler> <optimization_flag>"
    exit 1
fi

COMPILER=$1
FLAGS=$2

# Check if there are any .c files in the directory
if ls *.c &> /dev/null; then
    for file in *.c; do
        obj_file="${file%}_${COMPILER}_${FLAGS}"
	obj_file=$(echo "$obj_file" | sed 's/[^a-zA-Z0-9]/_/g' | sed 's/_\+/-/g')
        echo "Compiling $file -> $obj_file with $COMPILER and $OPTIMIZATION_FLAG"
        $COMPILER -c "$file" $FLAGS -o "../obj/$obj_file.o"
        if [ $? -ne 0 ]; then
            echo "Compilation failed for $file"
            exit 1
        fi
    done
    echo "All files compiled successfully."
else
    echo "No .c files found in the current directory."
    exit 2
fi
