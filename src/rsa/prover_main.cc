#include <stddef.h>
#include <stdint.h>

#include <chrono>
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
  auto start_time = std::chrono::high_resolution_clock::now();
  constexpr size_t MaxDegree = (size_t{1} << 32) - 1;
  using Domain = math::UnivariateEvaluationDomain<F, MaxDegree>;

  Curve::Init();

  auto zkey_start_time = std::chrono::high_resolution_clock::now();
  zk::r1cs::groth16::ProvingKey<Curve> proving_key;
  zk::r1cs::ConstraintMatrices<F> constraint_matrices;
  {
    ZKeyParser zkey_parser;
    std::unique_ptr<ZKey> zkey =
        zkey_parser.Parse(base::FilePath("circuits/rsa/rsa_main.zkey"));
    CHECK(zkey);

    proving_key = std::move(*zkey).TakeProvingKey().ToNativeProvingKey<Curve>();
    constraint_matrices =
        std::move(*zkey).TakeConstraintMatrices().ToNative<F>();
  }

  auto zkey_end_time = std::chrono::high_resolution_clock::now();
  auto zkey_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      zkey_end_time - zkey_start_time);

  std::cout << "zkey time: " << zkey_duration.count() << " milliseconds"
            << std::endl;

  auto load_start_time = std::chrono::high_resolution_clock::now();

  WitnessLoader<F> witness_loader(
      base::FilePath("circuits/rsa/rsa_main_cpp/rsa_main.dat"));

  // Signature values
  std::vector<F> signature = {
      F(3582320600048169363ULL),  F(7163546589759624213ULL),
      F(18262551396327275695ULL), F(4479772254206047016ULL),
      F(1970274621151677644ULL),  F(6547632513799968987ULL),
      F(921117808165172908ULL),   F(7155116889028933260ULL),
      F(16769940396381196125ULL), F(17141182191056257954ULL),
      F(4376997046052607007ULL),  F(17471823348423771450ULL),
      F(16282311012391954891ULL), F(70286524413490741ULL),
      F(1588836847166444745ULL),  F(15693430141227594668ULL),
      F(13832254169115286697ULL), F(15936550641925323613ULL),
      F(323842208142565220ULL),   F(6558662646882345749ULL),
      F(15268061661646212265ULL), F(14962976685717212593ULL),
      F(15773505053543368901ULL), F(9586594741348111792ULL),
      F(1455720481014374292ULL),  F(13945813312010515080ULL),
      F(6352059456732816887ULL),  F(17556873002865047035ULL),
      F(2412591065060484384ULL),  F(11512123092407778330ULL),
      F(8499281165724578877ULL),  F(12768005853882726493ULL)};

  // Modulus values
  std::vector<F> modulus = {
      F(13792647154200341559ULL), F(12773492180790982043ULL),
      F(13046321649363433702ULL), F(10174370803876824128ULL),
      F(7282572246071034406ULL),  F(1524365412687682781ULL),
      F(4900829043004737418ULL),  F(6195884386932410966ULL),
      F(13554217876979843574ULL), F(17902692039595931737ULL),
      F(12433028734895890975ULL), F(15971442058448435996ULL),
      F(4591894758077129763ULL),  F(11258250015882429548ULL),
      F(16399550288873254981ULL), F(8246389845141771315ULL),
      F(14040203746442788850ULL), F(7283856864330834987ULL),
      F(12297563098718697441ULL), F(13560928146585163504ULL),
      F(7380926829734048483ULL),  F(14591299561622291080ULL),
      F(8439722381984777599ULL),  F(17375431987296514829ULL),
      F(16727607878674407272ULL), F(3233954801381564296ULL),
      F(17255435698225160983ULL), F(15093748890170255670ULL),
      F(15810389980847260072ULL), F(11120056430439037392ULL),
      F(5866130971823719482ULL),  F(13327552690270163501ULL)};

  // Base message values
  std::vector<F> base_message = {F(18114495772705111902ULL),
                                 F(2254271930739856077ULL),
                                 F(2068851770ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL),
                                 F(0ULL)};
  witness_loader.Set("signature", signature);
  witness_loader.Set("modulus", modulus);
  witness_loader.Set("base_message", base_message);
  // witness_loader.Set("in", Uint8ToBitVector<F>(in));
  witness_loader.Load();
  auto load_end_time = std::chrono::high_resolution_clock::now();
  auto load_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      load_end_time - load_start_time);

  std::cout << "load wtns time: " << load_duration.count() << " milliseconds"
            << std::endl;

  auto wtns_start_time = std::chrono::high_resolution_clock::now();
  std::vector<F> full_assignments = base::CreateVector(
      constraint_matrices.num_instance_variables +
          constraint_matrices.num_witness_variables,
      [&witness_loader](size_t i) { return witness_loader.Get(i); });

  absl::Span<const F> public_inputs =
      absl::MakeConstSpan(full_assignments)
          .subspan(1, constraint_matrices.num_instance_variables - 1);

  // CHECK_EQ(public_inputs.size(), size_t{256});
  // CheckPublicInput(in, public_inputs);

  std::unique_ptr<Domain> domain =
      Domain::Create(constraint_matrices.num_constraints +
                     constraint_matrices.num_instance_variables);
  std::vector<F> h_evals =
      QuadraticArithmeticProgram<F>::WitnessMapFromMatrices(
          domain.get(), constraint_matrices, full_assignments);
  auto wtns_end_time = std::chrono::high_resolution_clock::now();
  auto wtns_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      wtns_end_time - wtns_start_time);

  std::cout << "calc witness time: " << wtns_duration.count() << " milliseconds"
            << std::endl;

  auto prove_start_time = std::chrono::high_resolution_clock::now();
  zk::r1cs::groth16::Proof<Curve> proof =
      zk::r1cs::groth16::CreateProofWithAssignmentZK(
          proving_key, absl::MakeConstSpan(h_evals),
          absl::MakeConstSpan(full_assignments)
              .subspan(1, constraint_matrices.num_instance_variables - 1),
          absl::MakeConstSpan(full_assignments)
              .subspan(constraint_matrices.num_instance_variables),
          absl::MakeConstSpan(full_assignments).subspan(1));
  auto prove_end_time = std::chrono::high_resolution_clock::now();
  auto prove_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      prove_end_time - prove_start_time);

  std::cout << "Prove time: " << prove_duration.count() << " milliseconds"
            << std::endl;

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  std::cout << "====Total time: " << duration.count()
            << " milliseconds====" << std::endl;
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
