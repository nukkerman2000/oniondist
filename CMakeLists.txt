cmake_minimum_required(VERSION 3.18)
project(oniondist LANGUAGES C CXX)

# --- common build settings ---
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

set(CORE_SRC
	src/crypto-ops-data.c
	src/crypto-ops.c
	src/keccak.cpp
)

include_directories(src)

# --- CPU client: always built, needs no CUDA ---
add_executable(vanity_cpu src/main_cpu.cpp ${CORE_SRC})
target_link_libraries(vanity_cpu PRIVATE Threads::Threads)

# --- CUDA targets: only when a CUDA compiler is present ---
include(CheckLanguage)
check_language(CUDA)
if(CMAKE_CUDA_COMPILER)
	enable_language(CUDA)
	if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
		set(CMAKE_CUDA_ARCHITECTURES 86)
	endif()
	set(CMAKE_CUDA_STANDARD 17)
	set(CMAKE_CUDA_STANDARD_REQUIRED ON)

	# original local vanity searcher (GPU + CPU pool)
	add_executable(vanity_torv3_cuda src/main.cu ${CORE_SRC})
	target_link_libraries(vanity_torv3_cuda PRIVATE Threads::Threads)

	# distributed GPU agent
	add_executable(vanity_gpu src/agent_gpu.cu ${CORE_SRC})
	target_link_libraries(vanity_gpu PRIVATE Threads::Threads)

	message(STATUS "CUDA found: building vanity_torv3_cuda and vanity_gpu (arch ${CMAKE_CUDA_ARCHITECTURES})")
else()
	message(STATUS "No CUDA compiler found: building CPU client only.")
endif()
