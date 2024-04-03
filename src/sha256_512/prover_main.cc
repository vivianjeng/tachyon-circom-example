#include <stddef.h>
#include <stdint.h>

#include <iostream>
#include <utility>
#include <vector>

#include "absl/types/span.h"
#include "openssl/sha.h"

#include "circomlib/circuit/quadratic_arithmetic_program.h"
#include "circomlib/circuit/witness_loader.h"
#include "circomlib/zkey/zkey_parser.h"
#include "tachyon/base/logging.h"
#include "tachyon/math/elliptic_curves/bn/bn254/bn254.h"
#include "tachyon/math/polynomials/univariate/univariate_evaluation_domain_factory.h"
#include "tachyon/zk/r1cs/groth16/prove.h"
#include "tachyon/zk/r1cs/groth16/verify.h"

namespace tachyon::circom {

using namespace math;

using F = bn254::Fr;
using Curve = math::bn254::BN254Curve;

template <typename F>
std::vector<F> Uint8ToBitVector(absl::Span<const uint8_t> uint8_vec) {
  std::vector<F> bit_vec;
  bit_vec.reserve(uint8_vec.size() * 8);
  for (size_t i = 0; i < uint8_vec.size(); i++) {
    for (size_t j = 0; j < 8; ++j) {
      bit_vec.push_back(F((uint8_vec[i] >> (7 - j)) & 1));
    }
  }
  return bit_vec;
}

template <typename F>
std::vector<uint8_t> BitToUint8Vector(absl::Span<const F> bit_vec) {
  std::vector<uint8_t> uint8_vec;
  size_t size = (bit_vec.size() + 7) / 8;
  uint8_vec.resize(size, 0);
  for (size_t i = 0; i < bit_vec.size(); i++) {
    size_t idx = i / 8;
    uint8_vec[idx] |= (bit_vec[i].ToBigInt()[0] << (7 - (i % 8)));
  }
  return uint8_vec;
}

void CheckPublicInput(const std::vector<uint8_t> &in,
                      absl::Span<const F> public_inputs) {
  SHA256_CTX state;
  SHA256_Init(&state);

  SHA256_Update(&state, in.data(), in.size());
  uint8_t result[SHA256_DIGEST_LENGTH];
  SHA256_Final(result, &state);

  std::vector<uint8_t> uint8_vec = BitToUint8Vector(public_inputs);
  std::vector<uint8_t> result_vec(std::begin(result), std::end(result));
  CHECK(uint8_vec == result_vec);
}

int RealMain(int argc, char **argv) {
  constexpr size_t MaxDegree = (size_t{1} << 16) - 1;
  using Domain = math::UnivariateEvaluationDomain<F, MaxDegree>;

  Curve::Init();

  WitnessLoader<F> witness_loader(
      base::FilePath("circuits/sha256_512/sha256_512_cpp/sha256_512.dat"));

  std::vector<uint8_t> in = base::CreateVector(
      64, [](size_t i) { return base::Uniform(base::Range<uint8_t>()); });
  witness_loader.Set("in", Uint8ToBitVector<F>(in));
  witness_loader.Load();

  zk::r1cs::groth16::ProvingKey<Curve> proving_key;
  zk::r1cs::ConstraintMatrices<F> constraint_matrices;
  {
    ZKeyParser zkey_parser;
    std::unique_ptr<ZKey> zkey = zkey_parser.Parse(
        base::FilePath("circuits/sha256_512/sha256_512.zkey"));
    CHECK(zkey);

    proving_key = std::move(*zkey).TakeProvingKey().ToNativeProvingKey<Curve>();
    constraint_matrices =
        std::move(*zkey).TakeConstraintMatrices().ToNative<F>();
  }

  std::vector<F> full_assignments = base::CreateVector(
      constraint_matrices.num_instance_variables +
          constraint_matrices.num_witness_variables,
      [&witness_loader](size_t i) { return witness_loader.Get(i); });

  absl::Span<const F> public_inputs =
      absl::MakeConstSpan(full_assignments)
          .subspan(1, constraint_matrices.num_instance_variables - 1);

  CHECK_EQ(public_inputs.size(), size_t{256});
  CheckPublicInput(in, public_inputs);

  std::unique_ptr<Domain> domain =
      Domain::Create(constraint_matrices.num_constraints +
                     constraint_matrices.num_instance_variables);
  std::vector<F> h_evals =
      QuadraticArithmeticProgram<F>::WitnessMapFromMatrices(
          domain.get(), constraint_matrices, full_assignments);

  zk::r1cs::groth16::Proof<Curve> proof =
      zk::r1cs::groth16::CreateProofWithAssignmentZK(
          proving_key, absl::MakeConstSpan(h_evals),
          absl::MakeConstSpan(full_assignments)
              .subspan(1, constraint_matrices.num_instance_variables - 1),
          absl::MakeConstSpan(full_assignments)
              .subspan(constraint_matrices.num_instance_variables),
          absl::MakeConstSpan(full_assignments).subspan(1));

  std::cout << proof.ToString() << std::endl;

  zk::r1cs::groth16::PreparedVerifyingKey<Curve> prepared_verifying_key =
      std::move(proving_key).TakeVerifyingKey().ToPreparedVerifyingKey();
  CHECK(zk::r1cs::groth16::VerifyProof(prepared_verifying_key, proof,
                                       public_inputs));
  return 0;
}

}  // namespace tachyon::circom

int main(int argc, char **argv) {
  return tachyon::circom::RealMain(argc, argv);
}
