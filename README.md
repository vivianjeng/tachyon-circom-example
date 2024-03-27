# Circom Example

## Prerequisites

```shell
git submodule update --init
```

### Bazel

Follow the instructions [here](https://bazel.build/install).

## How to run prover(on Linux)

```shell
bazel run --config linux //src:prover_main
```

## How to run prover(on Macos arm64)

```shell
bazel run --config macos_arm64 //src:prover_main
```

## How to run prover(on Macos x64)

```shell
bazel run --config macos_x86_64 //src:prover_main
```
