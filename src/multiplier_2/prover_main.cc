#include <stddef.h>
#include <stdint.h>

#include <iostream>
#include <utility>

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

int RealMain(int argc, char **argv) {
  constexpr size_t MaxDegree = (size_t{1} << 2) - 1;
  using Domain = math::UnivariateEvaluationDomain<F, MaxDegree>;

  Curve::Init();

  WitnessLoader<F> witness_loader(base::FilePath(
      "circuits/multiplier_2/multiplier_2_main_cpp/multiplier_2_main.dat"));

  F a = F::Random();
  F b = F::Random();
  witness_loader.Set("in1", a);
  witness_loader.Set("in2", b);
  witness_loader.Load();

  zk::r1cs::groth16::ProvingKey<Curve> proving_key;
  zk::r1cs::ConstraintMatrices<F> constraint_matrices;
  {
    ZKeyParser zkey_parser;
    std::unique_ptr<ZKey> zkey = zkey_parser.Parse(
        base::FilePath("circuits/multiplier_2/multiplier_2_main.zkey"));
    CHECK(zkey);

    proving_key = std::move(*zkey).TakeProvingKey().ToNativeProvingKey<Curve>();
    constraint_matrices =
        std::move(*zkey).TakeConstraintMatrices().ToNative<F>();
  }

  std::vector<F> full_assignments = base::CreateVector(
      constraint_matrices.num_instance_variables +
          constraint_matrices.num_witness_variables,
      [&witness_loader](size_t i) { return witness_loader.Get(i); });

  std::cout << full_assignments.size() << std::endl;
  CHECK_EQ(full_assignments[0], F(1));
  CHECK_EQ(full_assignments[1], a * b);
  CHECK_EQ(full_assignments[2], a);
  CHECK_EQ(full_assignments[3], b);

  absl::Span<const F> public_inputs =
      absl::MakeConstSpan(full_assignments)
          .subspan(1, constraint_matrices.num_instance_variables - 1);

  CHECK_EQ(public_inputs.size(), size_t{1});
  CHECK_EQ(public_inputs[0], a * b);

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
