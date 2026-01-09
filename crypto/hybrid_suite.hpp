#pragma once

#include "interfaces.hpp"

namespace pqauth {

CryptoSuite make_classical_suite();
CryptoSuite make_pq_suite();
CryptoSuite make_hybrid_suite();

} // namespace pqauth
