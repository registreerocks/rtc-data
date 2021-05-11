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
