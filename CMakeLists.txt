cmake_minimum_required(VERSION 3.16)
project(pq_auth_server LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

# Optional: GSS-API for mech_pqauth mechanism
find_package(GSSAPI)

add_executable(pq_authd
    cmd/pq-authd/main.cpp
    as/as_server.cpp
    tgs/tgs_server.cpp
    audit/audit_logger.cpp
    crypto/hkdf_sha3.cpp
    crypto/classical_providers.cpp
    crypto/pq_providers.cpp
    crypto/hybrid_suite.cpp
    crypto/ticket_protection.cpp
)
target_include_directories(pq_authd PRIVATE
    include
    as
    tgs
    crypto
    policy
    storage
    audit
)

target_link_libraries(pq_authd PRIVATE
    OpenSSL::Crypto
    oqs
)

# GSS-API mechanism plugin: mech_pqauth
#
# This builds a shared library intended to be installed under
#   /usr/lib/gssapi/mech_pqauth.so
# on Linux systems. It currently contains only a skeleton implementation
# of the required GSS-API entry points and does not perform any
# cryptographic operations or PQ-Auth daemon calls.
if(GSSAPI_FOUND)
    add_library(mech_pqauth SHARED
        gss/mech_pqauth.c
    )

    target_include_directories(mech_pqauth PRIVATE
        ${GSSAPI_INCLUDE_DIRS}
    )

    target_link_libraries(mech_pqauth PRIVATE
        ${GSSAPI_LIBRARIES}
    )

    # Install location matches the required Linux GSS-API mechanism path.
    install(TARGETS mech_pqauth
        LIBRARY DESTINATION /usr/lib/gssapi
    )
endif()
