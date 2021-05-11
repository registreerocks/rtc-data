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

CRATE_LIB_NAME := enclave
CRATE_BUILD_PATH := ./target/release
CODEGEN_PATH = /root/rtc-data/codegen/data_enclave
CUSTOM_BUILD_PATH := build
CUSTOM_LIBRARY_PATH := $(CUSTOM_BUILD_PATH)/lib
CUSTOM_BIN_PATH := $(CUSTOM_BUILD_PATH)/bin

Crate_Files := $(wildcard src/*.rs)
Out_StaticLib := $(CRATE_BUILD_PATH)/lib$(CRATE_LIB_NAME).a
Out_Bindings := $(CODEGEN_PATH)/bindings.h

Out_EdgeObject := $(CUSTOM_LIBRARY_PATH)/Enclave_t.o
Out_Dylib := $(CUSTOM_LIBRARY_PATH)/enclave.so
Out_SignedDylib := $(CUSTOM_BIN_PATH)/enclave.signed.so

Out_CodegenFiles := $(CODEGEN_PATH)/Enclave_t.c $(CODEGEN_PATH)/Enclave_t.h $(CODEGEN_PATH)/Enclave_u.c $(CODEGEN_PATH)/Enclave_u.h

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
	cargo build --release

$(Out_CodegenFiles): $(SGX_EDGER8R) ./Enclave.edl $(Out_Bindings) | $(CODEGEN_PATH)
	$(SGX_EDGER8R) ./Enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_EDL_PATH) --trusted-dir $(CODEGEN_PATH) --untrusted-dir $(CODEGEN_PATH)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

$(Out_EdgeObject): $(Out_CodegenFiles) | $(CODEGEN_PATH) $(CUSTOM_LIBRARY_PATH)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(CODEGEN_PATH)/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(Out_Dylib): $(Out_StaticLib) $(Out_EdgeObject) | $(CUSTOM_LIBRARY_PATH)
	@$(CXX) $(Out_EdgeObject) -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Out_SignedDylib): $(Out_Dylib) | $(CUSTOM_BIN_PATH)
	@$(SGX_ENCLAVE_SIGNER) sign -key ./Enclave_private.pem -enclave $(Out_Dylib) -out $@ -config ./Enclave.config.xml
	@echo "SIGN =>  $@"
	@echo "====================\n\nBuilt Enclave with SGX_MODE $(SGX_MODE)\n"
