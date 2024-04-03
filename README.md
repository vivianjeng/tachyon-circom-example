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

## How to run

```shell
bazel run //src:prover_main
```

## How to compile circom

This task is automatically called when running `//src:prover_main`, but you can also compile a circuit manually like this example below.

```shell
bazel build //circuits:compile_multiplier_2
```

As a result, these 3 files are generated.

- `bazel-bin/circuits/multiplier_2.r1cs`
- `bazel-bin/circuits/multiplier_2_cpp/multiplier_2.cpp`
- `bazel-bin/circuits/multiplier_2_cpp/multiplier_2.dat`
