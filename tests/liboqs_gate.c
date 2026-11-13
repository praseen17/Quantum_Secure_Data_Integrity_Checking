#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_signature_algorithm(const char *name) {
  OQS_SIG *sig = OQS_SIG_new(name);
  if (sig == NULL) {
    fprintf(stderr, "cannot initialize %s\n", name);
    return 1;
  }

  uint8_t *public_key = OQS_MEM_malloc(sig->length_public_key);
  uint8_t *secret_key = OQS_MEM_malloc(sig->length_secret_key);
  uint8_t *wrong_public_key = OQS_MEM_malloc(sig->length_public_key);
  uint8_t *wrong_secret_key = OQS_MEM_malloc(sig->length_secret_key);
  uint8_t *signature = OQS_MEM_malloc(sig->length_signature);
  const uint8_t message[] = "Q-SAFE liboqs runtime gate";
  uint8_t changed_message[sizeof(message)];
  memcpy(changed_message, message, sizeof(message));
  changed_message[0] ^= 1;
  size_t signature_length = 0;
  int result = 1;

  if (public_key == NULL || secret_key == NULL || wrong_public_key == NULL ||
      wrong_secret_key == NULL || signature == NULL) {
    fprintf(stderr, "allocation failed for %s\n", name);
    goto cleanup;
  }

  if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS ||
      OQS_SIG_keypair(sig, wrong_public_key, wrong_secret_key) != OQS_SUCCESS) {
    fprintf(stderr, "key generation failed for %s\n", name);
    goto cleanup;
  }

  if (OQS_SIG_sign(sig, signature, &signature_length, message, sizeof(message), secret_key) !=
      OQS_SUCCESS) {
    fprintf(stderr, "signing failed for %s\n", name);
    goto cleanup;
  }

  if (OQS_SIG_verify(sig, message, sizeof(message), signature, signature_length, public_key) !=
          OQS_SUCCESS ||
      OQS_SIG_verify(sig, changed_message, sizeof(changed_message), signature, signature_length,
                     public_key) == OQS_SUCCESS ||
      OQS_SIG_verify(sig, message, sizeof(message), signature, signature_length, wrong_public_key) ==
          OQS_SUCCESS) {
    fprintf(stderr, "verification checks failed for %s\n", name);
    goto cleanup;
  }

  printf("%s: keygen/sign/verify passed; modified message and wrong key rejected; "
         "public key=%zu bytes signature=%zu bytes\n",
         name, sig->length_public_key, signature_length);
  result = 0;

cleanup:
  OQS_MEM_secure_free(secret_key, sig->length_secret_key);
  OQS_MEM_secure_free(wrong_secret_key, sig->length_secret_key);
  OQS_MEM_insecure_free(public_key);
  OQS_MEM_insecure_free(wrong_public_key);
  OQS_MEM_insecure_free(signature);
  OQS_SIG_free(sig);
  return result;
}

int main(void) {
  const char *names[] = {"ML-DSA-44", "ML-DSA-65", "Dilithium2", "Dilithium3"};
  int enabled_count = 0;
  int failure_count = 0;

  printf("liboqs version %s\n", OQS_version());
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    int enabled = OQS_SIG_alg_is_enabled(names[i]);
    printf("%s: %s\n", names[i], enabled ? "enabled" : "disabled");
    if (enabled) {
      ++enabled_count;
      failure_count += check_signature_algorithm(names[i]);
    }
  }

  if (enabled_count == 0) {
    fprintf(stderr, "no requested signature algorithm is enabled\n");
    return 1;
  }
  return failure_count == 0 ? 0 : 1;
}
