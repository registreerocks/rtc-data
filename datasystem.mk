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

include ./prelude.mk
######## CUSTOM Settings ########

BUILD_PROFILE ?= DEBUG

CUSTOM_BUILD_PATH := $(BUILD_PATH)/data_system
CUSTOM_LIBRARY_PATH := $(CUSTOM_BUILD_PATH)/lib
CUSTOM_BIN_PATH := $(CUSTOM_BUILD_PATH)/bin

ENCLAVE_PATH := ./rtc_data_enclave
APP_PATH := ./rtc_data_service
######## EDL Settings ########

Enclave_EDL_Files := $(ENCLAVE_PATH)/Enclave_t.c $(ENCLAVE_PATH)/Enclave_t.h $(APP_PATH)/Enclave_u.c $(APP_PATH)/Enclave_u.h

######## APP Settings ########

ifeq ($(BUILD_PROFILE), RELEASE)
	# App_Rust_Flags := --release
	# App_Rust_Path := ./target/release
else
	App_Rust_Flags :=
	App_Rust_Path := ./target/debug
endif

App_SRC_Files := $(shell find $(APP_PATH)/ -type f -name '*.rs') $(shell find $(APP_PATH)/ -type f -name 'Cargo.toml')
App_Include_Paths := -I ./$(APP_PATH) -I./include -I$(SGX_SDK)/include -I$(RUST_EDL_PATH)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Enclave_u_Object := $(CUSTOM_LIBRARY_PATH)/libEnclave_u.a
App_Name := $(CUSTOM_BIN_PATH)/rtc_data_service

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard ./$(ENCLAVE_PATH)/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(RUST_COMMON_PATH)/inc -I$(RUST_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./$(ENCLAVE_PATH) -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -l${ProtectedFs_Library_Name} -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tcxx -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=$(ENCLAVE_PATH)/Enclave.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave_Name := $(ENCLAVE_PATH)/enclave.so
Signed_RustEnclave_Name := $(CUSTOM_BIN_PATH)/enclave.signed.so

.PHONY: all
all: $(App_Name) $(Signed_RustEnclave_Name)

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) $(ENCLAVE_PATH)/Enclave.edl
	$(SGX_EDGER8R) --trusted $(ENCLAVE_PATH)/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_EDL_PATH) --trusted-dir $(ENCLAVE_PATH)
	$(SGX_EDGER8R) --untrusted $(ENCLAVE_PATH)/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(RUST_EDL_PATH) --untrusted-dir $(APP_PATH)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## Directories ########

build:
	mkdir -p $(BUILD_PATH) &&	mkdir -p $(CUSTOM_BUILD_PATH)

lib: build
	mkdir -p $(CUSTOM_LIBRARY_PATH)

bin: build
	mkdir -p $(CUSTOM_BIN_PATH)

######## App Objects ########

$(APP_PATH)/Enclave_u.o: $(Enclave_EDL_Files)
	@$(CC) $(App_C_Flags) -c $(APP_PATH)/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(App_Enclave_u_Object): $(APP_PATH)/Enclave_u.o | lib
	$(AR) rcsD $@ $^

$(App_Name): $(App_Enclave_u_Object) $(App_SRC_Files) | bin
	@cd $(APP_PATH) && SGX_SDK=$(SGX_SDK) cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	cp $(App_Rust_Path)/rtc_data_service $(CUSTOM_BIN_PATH)

######## Enclave Objects ########

$(ENCLAVE_PATH)/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(ENCLAVE_PATH)/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): $ enclave $(ENCLAVE_PATH)/Enclave_t.o
	@$(CXX) $(ENCLAVE_PATH)/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name) | bin
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_PATH)/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config $(ENCLAVE_PATH)/Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave
enclave:
	$(MAKE) -C $(ENCLAVE_PATH)/


.PHONY: clean
clean:
	@rm -f $(App_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) $(Qpl_Name) $(ENCLAVE_PATH)/*_t.* $(APP_PATH)/*_u.* $(CUSTOM_LIBRARY_PATH)/*.a
	@cd $(ENCLAVE_PATH) && cargo clean
	@cd $(APP_PATH) && cargo clean
	@rm -df $(CUSTOM_LIBRARY_PATH)
	@rm -df $(CUSTOM_BIN_PATH)
	@rm -df $(CUSTOM_BUILD_PATH)
	@rm -df $(BUILD_PATH)
