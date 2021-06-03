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

typedef enum ExecTokenError {
  EXEC_TOKEN_ERROR_GENERATE,
  EXEC_TOKEN_ERROR_VALIDATION,
  EXEC_TOKEN_ERROR_OUTPUT_BUFFER_SIZE,
  EXEC_TOKEN_ERROR_CRYPTO,
  EXEC_TOKEN_ERROR_IO,
} ExecTokenError;

typedef uint8_t Nonce[24];

/**
 * FFI safe result type that can be converted to and from a rust result.
 */
typedef enum EcallResult_Nonce__ExecTokenError_Tag {
  ECALL_RESULT_NONCE_EXEC_TOKEN_ERROR_OK_NONCE_EXEC_TOKEN_ERROR,
  ECALL_RESULT_NONCE_EXEC_TOKEN_ERROR_ERR_NONCE_EXEC_TOKEN_ERROR,
} EcallResult_Nonce__ExecTokenError_Tag;

typedef struct EcallResult_Nonce__ExecTokenError {
  EcallResult_Nonce__ExecTokenError_Tag tag;
  union {
    struct {
      Nonce ok;
    };
    struct {
      enum ExecTokenError err;
    };
  };
} EcallResult_Nonce__ExecTokenError;

typedef struct EcallResult_Nonce__ExecTokenError IssueTokenResult;

typedef struct ExecReqMetadata {
  uint8_t uploader_pub_key[32];
  Nonce nonce;
} ExecReqMetadata;

typedef uint8_t RecommendedAesGcmIv[12];

typedef struct SetAccessKeyEncryptedResponse {
  sgx_aes_gcm_128bit_tag_t tag;
  uint8_t ciphertext[SET_ACCESS_KEY_RESPONSE_SIZE];
  uint8_t aad[0];
  RecommendedAesGcmIv nonce;
} SetAccessKeyEncryptedResponse;

/**
 * Failed to acquire session / protected channel.
 *
 * See: `rtc_tenclave::dh::sessions::DhSessions`
 */
typedef enum AcquireSessionError_Tag {
  /**
   * This should generally be treated as an unrecoverable error.
   */
  ACQUIRE_SESSION_ERROR_CHANNEL_MUTEX_POISONED,
  ACQUIRE_SESSION_ERROR_NO_ACTIVE_SESSION,
  ACQUIRE_SESSION_ERROR_SGX,
} AcquireSessionError_Tag;

typedef struct AcquireSessionError {
  AcquireSessionError_Tag tag;
  union {
    struct {
      sgx_enclave_id_t no_active_session;
    };
    struct {
      sgx_status_t sgx;
    };
  };
} AcquireSessionError;

typedef enum SealingError_Tag {
  SEALING_ERROR_CHANNEL_NOT_FOUND,
  SEALING_ERROR_RKYV_BUFFER_SERIALIZER_ERROR,
  SEALING_ERROR_SGX,
} SealingError_Tag;

typedef struct SealingError {
  SealingError_Tag tag;
  union {
    struct {
      struct AcquireSessionError channel_not_found;
    };
    struct {
      sgx_status_t sgx;
    };
  };
} SealingError;

/**
 * FFI safe result type that can be converted to and from a rust result.
 */
typedef enum EcallResult_SetAccessKeyEncryptedResponse__SealingError_Tag {
  ECALL_RESULT_SET_ACCESS_KEY_ENCRYPTED_RESPONSE_SEALING_ERROR_OK_SET_ACCESS_KEY_ENCRYPTED_RESPONSE_SEALING_ERROR,
  ECALL_RESULT_SET_ACCESS_KEY_ENCRYPTED_RESPONSE_SEALING_ERROR_ERR_SET_ACCESS_KEY_ENCRYPTED_RESPONSE_SEALING_ERROR,
} EcallResult_SetAccessKeyEncryptedResponse__SealingError_Tag;

typedef struct EcallResult_SetAccessKeyEncryptedResponse__SealingError {
  EcallResult_SetAccessKeyEncryptedResponse__SealingError_Tag tag;
  union {
    struct {
      struct SetAccessKeyEncryptedResponse ok;
    };
    struct {
      struct SealingError err;
    };
  };
} EcallResult_SetAccessKeyEncryptedResponse__SealingError;

typedef struct EcallResult_SetAccessKeyEncryptedResponse__SealingError SetAccessKeyResult;

typedef struct SetAccessKeyEncryptedRequest {
  sgx_aes_gcm_128bit_tag_t tag;
  uint8_t ciphertext[SET_ACCESS_KEY_REQUEST_SIZE];
  uint8_t aad[ARCHIVED_ENCLAVE_ID_SIZE];
  RecommendedAesGcmIv nonce;
} SetAccessKeyEncryptedRequest;

/**
 * FFI safe result type that can be converted to and from a rust result.
 */
typedef enum EcallResult_sgx_dh_msg1_t__sgx_status_t_Tag {
  ECALL_RESULT_SGX_DH_MSG1_T_SGX_STATUS_T_OK_SGX_DH_MSG1_T_SGX_STATUS_T,
  ECALL_RESULT_SGX_DH_MSG1_T_SGX_STATUS_T_ERR_SGX_DH_MSG1_T_SGX_STATUS_T,
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
  ECALL_RESULT_SGX_DH_MSG3_T_SGX_STATUS_T_OK_SGX_DH_MSG3_T_SGX_STATUS_T,
  ECALL_RESULT_SGX_DH_MSG3_T_SGX_STATUS_T_ERR_SGX_DH_MSG3_T_SGX_STATUS_T,
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
  CREATE_REPORT_RESULT_SUCCESS,
  CREATE_REPORT_RESULT_SGX,
  CREATE_REPORT_RESULT_FAILED_TO_GET_PUBLIC_KEY,
  CREATE_REPORT_RESULT_FAILED_ENCODE_PUBLIC_KEY,
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
