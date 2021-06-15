#define RSA3072_PKCS8_DER_SIZE 420

#define ENCLAVE_HELD_PUB_KEY_SIZE 32

/**
 * Size of all the enclave held data shared and validated during attestation
 */
#define ENCLAVE_HELD_DATA_SIZE ENCLAVE_HELD_PUB_KEY_SIZE

/**
 * 16 byte MAC + encrypted payload (24 byte data access key + 16 byte UUID)
 */
#define DATA_UPLOAD_RESPONSE_LEN (16 + (24 + 16))

#define ARCHIVED_ENCLAVE_ID_SIZE 8

#define SET_ACCESS_KEY_REQUEST_SIZE 40

#define SET_ACCESS_KEY_RESPONSE_SIZE 1

typedef struct DataUploadResponse {
  uint8_t ciphertext[DATA_UPLOAD_RESPONSE_LEN];
  uint8_t nonce[24];
} DataUploadResponse;

typedef enum CryptoError_Tag {
  Rand,
  Unknown,
} CryptoError_Tag;

typedef struct CryptoError {
  CryptoError_Tag tag;
  union {
    struct {
      uint32_t rand;
    };
  };
} CryptoError;

typedef enum DataUploadError_Tag {
  Validation,
  Sealing,
  Crypto,
} DataUploadError_Tag;

typedef struct DataUploadError {
  DataUploadError_Tag tag;
  union {
    struct {
      sgx_status_t sealing;
    };
    struct {
      struct CryptoError crypto;
    };
  };
} DataUploadError;

/**
 * FFI safe result type that can be converted to and from a rust result.
 */
typedef enum EcallResult_DataUploadResponse__DataUploadError_Tag {
  Ok_DataUploadResponse__DataUploadError,
  Err_DataUploadResponse__DataUploadError,
} EcallResult_DataUploadResponse__DataUploadError_Tag;

typedef struct EcallResult_DataUploadResponse__DataUploadError {
  EcallResult_DataUploadResponse__DataUploadError_Tag tag;
  union {
    struct {
      struct DataUploadResponse ok;
    };
    struct {
      struct DataUploadError err;
    };
  };
} EcallResult_DataUploadResponse__DataUploadError;

typedef struct EcallResult_DataUploadResponse__DataUploadError DataUploadResult;

typedef struct UploadMetadata {
  uint8_t uploader_pub_key[32];
  uint8_t nonce[24];
} UploadMetadata;

/**
 * FFI safe result type that can be converted to and from a rust result.
 */
typedef enum EcallResult_sgx_dh_msg1_t__sgx_status_t_Tag {
  Ok_sgx_dh_msg1_t__sgx_status_t,
  Err_sgx_dh_msg1_t__sgx_status_t,
} EcallResult_sgx_dh_msg1_t__sgx_status_t_Tag;

typedef struct EcallResult_sgx_dh_msg1_t__sgx_status_t {
  EcallResult_sgx_dh_msg1_t__sgx_status_t_Tag tag;
  union {
    struct {
      sgx_dh_msg1_t ok;
    };
    struct {
      sgx_status_t err;
    };
  };
} EcallResult_sgx_dh_msg1_t__sgx_status_t;

typedef struct EcallResult_sgx_dh_msg1_t__sgx_status_t SessionRequestResult;

/**
 * FFI safe result type that can be converted to and from a rust result.
 */
typedef enum EcallResult_sgx_dh_msg3_t__sgx_status_t_Tag {
  Ok_sgx_dh_msg3_t__sgx_status_t,
  Err_sgx_dh_msg3_t__sgx_status_t,
} EcallResult_sgx_dh_msg3_t__sgx_status_t_Tag;

typedef struct EcallResult_sgx_dh_msg3_t__sgx_status_t {
  EcallResult_sgx_dh_msg3_t__sgx_status_t_Tag tag;
  union {
    struct {
      sgx_dh_msg3_t ok;
    };
    struct {
      sgx_status_t err;
    };
  };
} EcallResult_sgx_dh_msg3_t__sgx_status_t;

typedef struct EcallResult_sgx_dh_msg3_t__sgx_status_t ExchangeReportResult;

typedef enum CreateReportResult_Tag {
  Success,
  Sgx,
  FailedToGetPublicKey,
  FailedEncodePublicKey,
} CreateReportResult_Tag;

typedef struct CreateReportResult {
  CreateReportResult_Tag tag;
  union {
    struct {
      sgx_status_t sgx;
    };
  };
} CreateReportResult;

typedef uint8_t EnclaveHeldData[ENCLAVE_HELD_DATA_SIZE];
