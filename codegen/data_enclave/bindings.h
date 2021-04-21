#define PUBKEY_SIZE (SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE)

#define RSA3072_PKCS8_DER_SIZE 420

/**
 * Return result when creating a report
 *
 * This enum will be represented as a tagged union C type
 * see: https://github.com/rust-lang/rfcs/blob/master/text/2195-really-tagged-unions.md
 * Also see EDL file
 *
 * The only reason the C type is defined in the EDL is for the correct size of the type to be copied over.
 * We might be able to work around this if we just use an opaque int type with the same size as `size_of::<CreateReportResult>`.
 *
 * Maintainability of types like this pose a problem, since the edl will have to be updated whenever the type change. We might be
 * able to work around this if we use cbindgen to create a header file that is imported by the .edl file
 * TODO: Review above, add cbindgen to build steps?
 */
enum CreateReportResult_Tag {
  Success,
  Sgx,
  FailedToGetPublicKey,
  FailedEncodePublicKey,
};
typedef uint32_t CreateReportResult_Tag;

typedef struct CreateReportResult {
  CreateReportResult_Tag tag;
  union {
    struct {
      sgx_status_t sgx;
    };
  };
} CreateReportResult;
