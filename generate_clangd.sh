#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage: $0 <directory>"
	exit 1
fi

DIRECTORY=$(realpath $1)
OUTPUT_FILE=${DIRECTORY}"/.clangd"

echo "CompileFlags:" >"$OUTPUT_FILE"
echo "  Add:" >>"$OUTPUT_FILE"

find "$DIRECTORY" -type f -name "*.h" | while read file; do
	dir=$(dirname "$file")
	output_line="  - \"--include-directory=$dir\""
	if ! grep -Fxq "$output_line" "$OUTPUT_FILE"; then
		echo "$output_line" >>"$OUTPUT_FILE"
	fi
done
