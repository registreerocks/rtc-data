# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

TOP_DIR = ../
include ../prelude.mk

ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
export MITIGATION_CVE_2020_0551=LOAD
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
export MITIGATION_CVE_2020_0551=CF
endif

ENCLAVE_NAME = rtc_exec
CRATE_LIB_NAME := enclave
CRATE_BUILD_PATH := ./target/release
CODEGEN_PATH = /root/rtc-data/codegen/exec_enclave
CUSTOM_BUILD_PATH := build
CUSTOM_LIBRARY_PATH := $(CUSTOM_BUILD_PATH)/lib
CUSTOM_BIN_PATH := $(CUSTOM_BUILD_PATH)/bin

# XXX: Is there a better way to express this source dependency on rtc_tenclave?
Crate_Files := $(wildcard src/*.rs ../rtc_tenclave/src/*.rs)
Out_StaticLib := $(CRATE_BUILD_PATH)/lib$(CRATE_LIB_NAME).a
Out_Bindings := $(CODEGEN_PATH)/bindings.h

Out_EdgeObject := $(CUSTOM_LIBRARY_PATH)/$(ENCLAVE_NAME)_t.o
Out_Dylib := $(CUSTOM_LIBRARY_PATH)/enclave.so
Out_SignedDylib := $(CUSTOM_BIN_PATH)/enclave.signed.so

Out_CodegenFiles := $(CODEGEN_PATH)/$(ENCLAVE_NAME)_t.c $(CODEGEN_PATH)/$(ENCLAVE_NAME)_t.h $(CODEGEN_PATH)/$(ENCLAVE_NAME)_u.c $(CODEGEN_PATH)/$(ENCLAVE_NAME)_u.h

.PHONY: all

all: $(Out_SignedDylib)

SGX_MODE ?= HW

ifeq ($(SGX_MODE), SW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_Include_Paths := -I$(RUST_COMMON_PATH)/inc -I$(RUST_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I $(CODEGEN_PATH) -I./include

RustEnclave_Link_Libs := -L$(CRATE_BUILD_PATH) -l$(CRATE_LIB_NAME)
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -l${ProtectedFs_Library_Name} -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tcxx -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=./Enclave.lds \
	$(ENCLAVE_LDFLAGS)


######## Directories ########

$(CUSTOM_LIBRARY_PATH):
	mkdir -p $(CUSTOM_LIBRARY_PATH)

$(CUSTOM_BIN_PATH):
	mkdir -p $(CUSTOM_BIN_PATH)

$(CODEGEN_PATH):
	mkdir -p $(CODEGEN_PATH)

####### Enclave Build ########
$(Out_StaticLib) $(Out_Bindings): $(Crate_Files)
	# XXX: Make sure cargo build refreshes the output files when this rule executes.
	#
	# Currently, it's possible for make to consider the output files out of date,
	# while cargo considers the build up to date, because cargo resolves with more nuance
	# than the crude wildcard function in Crate_Files. When this happens, make gets stuck
	# trying to re-run this rule, without cargo touching the output files.
	#
	# To avoid this edge case, remove the two output files before invoking cargo build.
	# This ensures that cargo build recreates them, with timestamps that satisfy make.
	#
	@rm -f $(Out_StaticLib) $(Out_Bindings)
	cargo build --release

# See "ECALL enclave name prefixing and --use-prefix" in HACKING.md
$(Out_CodegenFiles): $(SGX_EDGER8R) ./$(ENCLAVE_NAME).edl $(Out_Bindings) | $(CODEGEN_PATH)
	$(SGX_EDGER8R) --use-prefix ./$(ENCLAVE_NAME).edl --search-path $(SGX_SDK)/include --search-path $(RUST_EDL_PATH) --search-path $(RTC_EDL_PATH) --trusted-dir $(CODEGEN_PATH) --untrusted-dir $(CODEGEN_PATH)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

$(Out_EdgeObject): $(Out_CodegenFiles) | $(CODEGEN_PATH) $(CUSTOM_LIBRARY_PATH)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(CODEGEN_PATH)/$(ENCLAVE_NAME)_t.c -o $@
	@echo "CC   <=  $<"

$(Out_Dylib): $(Out_StaticLib) $(Out_EdgeObject) | $(CUSTOM_LIBRARY_PATH)
	@$(CXX) $(Out_EdgeObject) -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Out_SignedDylib): $(Out_Dylib) | $(CUSTOM_BIN_PATH)
	@$(SGX_ENCLAVE_SIGNER) sign -key ./Enclave_private.pem -enclave $(Out_Dylib) -out $@ -config ./Enclave.config.xml
	@echo "SIGN =>  $@"
	@echo "====================\n\nBuilt Enclave with SGX_MODE $(SGX_MODE)\n"
