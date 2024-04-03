# Circom Example

## Prerequisites

1. Update submodules.

   ```shell
   git submodule update --init
   ```

1. Install prerequisite for [Tachyon](https://github.com/kroma-network/tachyon/) by following the [instructions](https://github.com/kroma-network/tachyon/blob/main/docs/how_to_use/how_to_build.md#prerequisites).

1. Install [snarkjs](https://github.com/iden3/snarkjs).

   ```shell
   npm install -g snarkjs@latest
   ```

1. Prepare `.bazelrc.user`.

   - On Linux

      ```shell
      echo "build --config linux" > .bazelrc.user
      echo "build --@kroma_network_tachyon//:has_openmp" >> .bazelrc.user
      ```

   - On Macos ARM64(After M1)

      ```shell
      echo "build --config macos_arm64" > .bazelrc.user
      ```

   - On Macos x86(Before M1)

      ```shell
      echo "build --config macos_x86_64" > .bazelrc.user
      ```

1. Sync the rust dependencies.

   ```shell
   CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
   ```

## Circuit Descriptions

- [adder.circom](/circuits/adder/adder.circom): It checks the addition of the two 32-bit unsigned integers. This circuit depends on [circomlib](https://github.com/kroma-network/circomlib) library.
- [multiplier_2_main.circom](/circuits/multiplier_2/multiplier_2_main.circom): It checks the multiplication of the two prime fields. This circuit is the first use case that uses [circom_library](https://github.com/kroma-network/rules_circom?tab=readme-ov-file#circom_library).
- [multiplier_3.circom](/circuits/multiplier_3/multiplier_3.circom): It checks the multiplication of the three prime fields. This circuit depends on [multiplier_2.circom](/circuits/multiplier_2/multiplier_2.circom).
- [sha256_512.circom](/circuits/sha256_512/sha256_512.circom): It checks the sha256 hash of the two 256-bit bytes. This circuit depends on [circomlib](https://github.com/kroma-network/circomlib) library.

## How to run

```shell
bazel run //src/{circuit_dir}:prover_main
```

`{circuit_dir}` should be one of these: `adder`, `multiplier_2`, `multiplier_3` or `sha256_512`.

## How to compile circom

This task is automatically called when running `//src/{circuit_dir}:prover_main`, but you can also compile a circuit manually like this example below.

```shell
bazel build //circuits/multiplier_2:compile_multiplier_2_main
```

As a result, these 3 files are generated.

- `bazel-bin/circuits/multiplier_2/multiplier_2_main.r1cs`
- `bazel-bin/circuits/multiplier_2/multiplier_2_main_cpp/multiplier_2_main.cpp`
- `bazel-bin/circuits/multiplier_2/multiplier_2_main_cpp/multiplier_2_main.dat`
