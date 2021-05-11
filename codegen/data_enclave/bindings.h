#define RSA3072_PKCS8_DER_SIZE 420

#define ENCLAVE_HELD_PUB_KEY_SIZE 32

/**
 * Size of all the enclave held data shared and validated during attestation
 */
#define ENCLAVE_HELD_DATA_SIZE ENCLAVE_HELD_PUB_KEY_SIZE

/**
 * (16 byte padding) + (password length) + (uuid)
 */
#define DATA_UPLOAD_RESPONSE_LEN ((24 + 16) + 16)

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
