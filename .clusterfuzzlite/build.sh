#!/bin/bash -eu

cd "$SRC/agentic-security-harness"

python3 -m pip install --require-hashes -r requirements/runtime.txt
python3 -m pip install --no-deps .

for fuzzer in $(find "$SRC/agentic-security-harness/fuzz" -name '*_fuzzer.py' | sort); do
  fuzzer_basename=$(basename -s .py "$fuzzer")
  fuzzer_package="${fuzzer_basename}.pkg"

  pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"

  cat > "$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput keeps this wrapper discoverable by ClusterFuzzLite.
this_dir=\$(dirname "\$0")
"\$this_dir/$fuzzer_package" "\$@"
EOF
  chmod +x "$OUT/$fuzzer_basename"
done

