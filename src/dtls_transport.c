#include <glib.h>

#include "utils.h"
#include "dtls_transport.h"

#define SRTP_MASTER_KEY_LENGTH  16
#define SRTP_MASTER_SALT_LENGTH 14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)

struct DtlsTransport {

  SSL *ssl;
  SSL_CTX *ssl_ctx;
  X509 *certificate;
  EVP_PKEY *private_key;
  BIO *read_bio;
  BIO *write_bio;

  srtp_policy_t remote_policy;
  srtp_policy_t local_policy;
  srtp_t srtp_in;
  srtp_t srtp_out;

  char fingerprint[160];

  gboolean handshake_done;
  gboolean srtp_init_done;
};


int cb_dtls_verify(int preverify_ok, X509_STORE_CTX *ctx) {

  gboolean dtls_selfsigned_certs_ok = TRUE;
  int err = X509_STORE_CTX_get_error(ctx);
  if(err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT || err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
    if(!dtls_selfsigned_certs_ok) {
      return 0;
    }
  }

  if(err == X509_V_ERR_CERT_HAS_EXPIRED)
    return 0;

  return dtls_selfsigned_certs_ok ? 1 : (err == X509_V_OK);
}

static X509 *certificate = NULL;
static EVP_PKEY *private_key = NULL;

char *cert_buf = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIICtTCCAZ2gAwIBAgIBADANBgkqhkiG9w0BAQUFADAeMQ0wCwYDVQQKDARUZXN0\n"
        "MQ0wCwYDVQQDDARUZXN0MB4XDTIxMTAxNzIwMzAwNFoXDTIzMTAxNzIwMzAwNFow\n"
        "HjENMAsGA1UECgwEVGVzdDENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEB\n"
        "BQADggEPADCCAQoCggEBALRDsYN7RsSYY0H3kYLIZ5NFZAJPWmXRNah6TC4ISiNS\n"
        "M++1gJKM0L3hRX/074dacY7u1ph5I0gY6+Jc+aUwih1q0jyPUCJro7gzjYE3IGN4\n"
        "aAiv0Yza6BcBwl8tcP21QKmfOnnfYlJjPBq5qdCHHcjAJ/VX0WGog7EVtfgzkHDq\n"
        "WDWCM6Vvs9z7m9s0g405Gw+pJF9re22yaKmEb7DvnMnTvjLXlKoylm8d26HdqkV/\n"
        "UR1AMTYbYu8jFZQW0qD8yMZbT8deU0XCLQRqzSRoC5gtjd/CmZxTKahe+nAv9EsK\n"
        "mHnAJvzpZ1BIBIA11kpuJP2ksypG2TK1SQoAGBGVnm8CAwEAATANBgkqhkiG9w0B\n"
        "AQUFAAOCAQEAHPN5zYfNUH6+aTWsHEGSEKmTh1oXX0AL/xfSeADkk1TsR3WSOv90\n"
        "sz89sNtF7M9xAVLSP+7VySqk3pf6s5nOG5nveNdxBiqcyiMm8/i0+TfwOx9qtdbA\n"
        "cni8skIK+eZTbzLwue5vqoes9QG/HwXyMTrPZzRMcso4QX9649VDdify6M3o2rrf\n"
        "cFW/onRr5fWE28SddQBF/Moai6T9iTHJofYMaFJPd6Jc2XQouWuoMADD2qOIhISa\n"
        "Tx95LBMMVRAIecshb24td7AzBzMg0cQOAVHlKT6VUy+bfZ3w59roY10jAO9MNXkm\n"
        "Igozc2CFYiHto3ZB57D+3LQ/A7uhTlZoqw==\n"
        "-----END CERTIFICATE-----\n"
        ;


char *pkey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0Q7GDe0bEmGNB\n"
        "95GCyGeTRWQCT1pl0TWoekwuCEojUjPvtYCSjNC94UV/9O+HWnGO7taYeSNIGOvi\n"
        "XPmlMIodatI8j1Aia6O4M42BNyBjeGgIr9GM2ugXAcJfLXD9tUCpnzp532JSYzwa\n"
        "uanQhx3IwCf1V9FhqIOxFbX4M5Bw6lg1gjOlb7Pc+5vbNIONORsPqSRfa3ttsmip\n"
        "hG+w75zJ074y15SqMpZvHduh3apFf1EdQDE2G2LvIxWUFtKg/MjGW0/HXlNFwi0E\n"
        "as0kaAuYLY3fwpmcUymoXvpwL/RLCph5wCb86WdQSASANdZKbiT9pLMqRtkytUkK\n"
        "ABgRlZ5vAgMBAAECggEACqcpeWyynPGohAB+b+0p+dES/PP1kqjPc/puQBYrU3UL\n"
        "LrJaO87okyAZ/FrcQPJ+XYUN14rpI9ydLA50jmeU8fIbJIsPoEkeLseVKDq6xkYa\n"
        "V9EUIC/boWhwNTG5SLUKcju/t+4UoGvO5IFuYK1rfC6m7d/Xtt6/kZqH23gopBOL\n"
        "wyjYRDZXbicyfUGYnqrgAG0fcf4NkxckCdEsLs4L3k6krKFPMBhK+yvgPQ9KloVD\n"
        "V98OPE8qMh+tNqNF7e/PApm7Qk7v5mKYcKzYhEMfXMY8ckMgnRLzNLvnTYyJIJXr\n"
        "aYCyCzoxVjWHcOII0Fr5zS9k2Fu3IR/BBsiYkzrmuQKBgQDvRmUmlqU9r38urAG4\n"
        "8VFEVwxLf9SdQsivwRUt4q9aXaFardW35gq79XPCe077ysd2gKivmncOz8NjSBD0\n"
        "dJ7HcHe7fo1Rs2ZxsajfuFnuTCTJPQr84d4PyvwyvVqKPAbYjeq6zpBQZQEcoFQh\n"
        "9byP0HegFCJgkT7aTRygiGyaiwKBgQDA3Vvh9Sumdoy13OZjvfrUt+CbU/TBq21y\n"
        "x7OrTPJquC0rDaJco+8R1dC9JUQ2MTnx74Ts7ZPnG1mowgr8br9fPA++Dl9Nf2vf\n"
        "EJLrKufePug7pXSYrtpYeyfzKVvyR6h3tq7qw9jz/g7Pp7uE+nuiyDsE9TA0XIeK\n"
        "y1Kv7e3cLQKBgQCM4moUeob49yhvlp+9AXnUP1zh53aM0hHQSmPqDJsrHg4vkkNQ\n"
        "cIbJfRCX5nrvDsq7H64zF0Qa2II3Juu0xCXpUHNvVmhnPraHIxBICggJo5PVWbfq\n"
        "hiN2MRKl3ZA97HIreARJ0e5vJ8mrzUs8Y7CPDTQicTh8m4jiiJzeePVZWQKBgBp+\n"
        "jj/FOWDdyki1duTe1VVhiTZtWyM71IY/DtyKbobglDvk3JgTYSU3FTzWoL89FfO5\n"
        "bq5JmNbXuAJp3a593EZN7u+x87+msH/tO/GYbE/onmiLOzA6XP5otL0/wkTPOUJw\n"
        "0yinDOe/z/MQ3L7Q1ikvjoQI1r1qtKgJdGt8qP9lAoGAGSXa/s1kPetQlbbQVljT\n"
        "g5wZvScoMCXQdvrL17slf+gY9N+wSqz7mF6M6JCXAg04fvFxp57ASI4+MUdmQmvN\n"
        "mDicNLdEjZ/S+s/4qsN7GTxU8lgAgDjavecfx3Dh7MMXIYvkzOcvL0dSl+HlqqeU\n"
        "UVXuCKQN8ShXzZO8XJXfzcI=\n"
        "-----END PRIVATE KEY-----\n";

void *serialize_cert(X509 *cert)
{
    size_t size = strlen(cert_buf) * 10;
    void *mem = calloc(size, 1);
    FILE *fp = fmemopen(mem, size, "w");
    PEM_write_X509(fp, cert);
    fclose(fp);
    
    return mem;
}

X509 *deserialize_cert(void *buf)
{
    size_t buf_size = strlen(buf);
    FILE *fp = fmemopen(buf, buf_size, "r");
    X509 *cert = X509_new();
    PEM_read_X509(fp, &cert, NULL, NULL);
    fclose(fp);
    return cert;
}

void *serialize_pkey(EVP_PKEY *key)
{
    size_t size = strlen(pkey) * 10;
    void *mem = calloc(size, 1);
    FILE *fp = fmemopen(mem, size, "w");
    int rv = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    
    return mem;
}

EVP_PKEY *deserialize_pkey(void *buf)
{
    size_t buf_size = strlen(buf);
    FILE *fp = fmemopen(buf, buf_size, "r");
    EVP_PKEY *pkey = EVP_PKEY_new();
    PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
    fclose(fp);
    return pkey;
}

void generate_self_certificate(DtlsTransport *dtls_transport)
{
    certificate = deserialize_cert(cert_buf);
    private_key = deserialize_pkey(pkey);
    
    /*void *ser_cer = serialize_cert(certificate);
    printf("%s\n", cert_buf);
    printf("%s\n", ser_cer);
    X509 *deser_cert = deserialize_cert(ser_cer);
    int cmp_cert = X509_cmp(certificate, deser_cert);
    
    void *ser_pkey = serialize_pkey(private_key);
    EVP_PKEY *deser_pkey = deserialize_pkey(ser_pkey);
    void *reser_pkey = serialize_pkey(deser_pkey);
    EVP_PKEY *redeser_pkey = deserialize_pkey(reser_pkey);
   
    int cmp_pkey = EVP_PKEY_cmp(private_key, deser_pkey);
    int cmp_pkey2 = EVP_PKEY_cmp(redeser_pkey, deser_pkey);
    
    printf("%s\n", pkey);
    printf("%s\n", ser_pkey);
    printf("%s\n", reser_pkey);
*/
    
    
    if(certificate != NULL)
    {
        dtls_transport->certificate = certificate;
        dtls_transport->private_key = private_key;
        return;
    }

  const int num_bits = 2048;
  BIGNUM *bne = NULL;
  RSA *rsa_key = NULL;
  X509_NAME *cert_name = NULL;
  //EC_KEY *ecc_key = NULL;

  dtls_transport->private_key = EVP_PKEY_new();
  if(dtls_transport->private_key == NULL) {
    LOG_ERROR();
  }
  bne = BN_new();
  if(!bne) {
    LOG_ERROR();
  }

  if(!BN_set_word(bne, RSA_F4)) {  /* RSA_F4 == 65537 */
    LOG_ERROR();
  }

  rsa_key = RSA_new();
  if(!rsa_key) {
    LOG_ERROR();
  }

  if(!RSA_generate_key_ex(rsa_key, num_bits, bne, NULL)) {
    LOG_ERROR();
  }

  if(!EVP_PKEY_assign_RSA(dtls_transport->private_key, rsa_key)) {
    LOG_ERROR();
  }

#warning
  rsa_key = NULL;

  dtls_transport->certificate = X509_new();
  if(!dtls_transport->certificate) {
    LOG_ERROR();
  }

  X509_set_version(dtls_transport->certificate, 2);


  X509_gmtime_adj(X509_get_notBefore(dtls_transport->certificate), -1 * 60*60*24*365);  /* -1 year */
  X509_gmtime_adj(X509_get_notAfter(dtls_transport->certificate), 60*60*24*365);  /* 1 year */

  if(!X509_set_pubkey(dtls_transport->certificate, dtls_transport->private_key)) {
    LOG_ERROR();
  }

  cert_name = X509_get_subject_name(dtls_transport->certificate);
  if(!cert_name) {
    LOG_ERROR();
  }
  X509_NAME_add_entry_by_txt(cert_name, "O", MBSTRING_ASC, (const unsigned char*)"Test", -1, -1, 0);
  X509_NAME_add_entry_by_txt(cert_name, "CN", MBSTRING_ASC, (const unsigned char*)"Test", -1, -1, 0);

  if(!X509_set_issuer_name(dtls_transport->certificate, cert_name)) {
    LOG_ERROR();
  }

  if(!X509_sign(dtls_transport->certificate, dtls_transport->private_key, EVP_sha1())) {
    LOG_ERROR();
  }
  certificate = dtls_transport->certificate;
  private_key = dtls_transport->private_key;

  BN_free(bne);

}

int dtls_transport_init(DtlsTransport *dtls_transport, BIO *agent_write_bio) {

  dtls_transport->ssl_ctx = SSL_CTX_new(DTLS_method());
  //SSL_CTX_set_ssl_version(dtls_transport->ssl_ctx, DTLS_client_method());
  SSL_CTX_set_verify(dtls_transport->ssl_ctx,
   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cb_dtls_verify);

  SSL_CTX_set_tlsext_use_srtp(dtls_transport->ssl_ctx, "SRTP_AES128_CM_SHA1_80");

  generate_self_certificate(dtls_transport);
  int rv = SSL_CTX_use_certificate(dtls_transport->ssl_ctx, dtls_transport->certificate);
  if(!rv) {
      unsigned long err = SSL_get_error(dtls_transport->ssl, rv);
      printf("handshake rv %d err %d\n", rv, (int)err);
    LOG_ERROR("use certificate failed");
    return -1;
  }

  if(!SSL_CTX_use_PrivateKey(dtls_transport->ssl_ctx, dtls_transport->private_key)) {
    LOG_ERROR("use private key failed");
    return -1;
  }
  if(!SSL_CTX_check_private_key(dtls_transport->ssl_ctx)) {
    LOG_ERROR("check preverify key failed");
    return -1;
  }
  SSL_CTX_set_read_ahead(dtls_transport->ssl_ctx, 1);

  unsigned int size;
  unsigned char fingerprint[EVP_MAX_MD_SIZE];
  if(X509_digest(dtls_transport->certificate, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
    LOG_ERROR("generate fingerprint failed");
    return -1;
  }

  char *lfp = (char *)&dtls_transport->fingerprint;
  unsigned int i = 0;
  for(i = 0; i < size; i++) {
    g_snprintf(lfp, 4, "%.2X:", fingerprint[i]);
    lfp += 3;
  }
  *(lfp-1) = 0;

  dtls_transport->ssl = SSL_new(dtls_transport->ssl_ctx);

  dtls_transport->read_bio = BIO_new(BIO_s_mem());
  dtls_transport->write_bio = agent_write_bio;
  BIO_set_mem_eof_return(dtls_transport->read_bio, -1);
  SSL_set_bio(dtls_transport->ssl, dtls_transport->read_bio, dtls_transport->write_bio);

  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(ecdh == NULL) {
    LOG_ERROR("New ecdh curve by name failed"); 
    return -1;
  }

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_ECDH_USE;
  SSL_set_options(dtls_transport->ssl, flags);
  SSL_set_tmp_ecdh(dtls_transport->ssl, ecdh);
  EC_KEY_free(ecdh);

  dtls_transport->handshake_done = FALSE;
  dtls_transport->srtp_init_done = FALSE;

  if(srtp_init() != srtp_err_status_ok) {
    LOG_ERROR("libsrtp init failed");
  }

  return 0;
}

DtlsTransport* dtls_transport_create(BIO *agent_write_bio) {

  DtlsTransport *dtls_transport = NULL;
  dtls_transport = (DtlsTransport*)malloc(sizeof(DtlsTransport));
  memset(dtls_transport, 0, sizeof(*dtls_transport));
  if(dtls_transport == NULL)
    return dtls_transport;

  dtls_transport_init(dtls_transport, agent_write_bio);
  return dtls_transport;
}

void dtls_transport_destroy(DtlsTransport *dtls_transport) {

  if(dtls_transport == NULL)
    return;

  SSL_CTX_free(dtls_transport->ssl_ctx);
  SSL_free(dtls_transport->ssl);
  X509_free(dtls_transport->certificate);
  EVP_PKEY_free(dtls_transport->private_key);

  if(dtls_transport->srtp_in)
    srtp_dealloc(dtls_transport->srtp_in);
  if(dtls_transport->srtp_out)
    srtp_dealloc(dtls_transport->srtp_out);

  srtp_shutdown();

  free(dtls_transport);
}

void dtls_transport_do_handshake(DtlsTransport *dtls_transport) {

  SSL_set_accept_state(dtls_transport->ssl);
  int res = SSL_do_handshake(dtls_transport->ssl);
  dtls_transport->handshake_done = TRUE;

  /*int b = SSL_do_handshake(dtls_transport->ssl);
  if(b == 1)
  {
      printf("handshake success\n");
      dtls_transport->handshake_done = TRUE;
  }
  else
  {
      unsigned long err = SSL_get_error(dtls_transport->ssl, b);
      printf("handshake rv %d err %d\n", b, (int)err);
      if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_READ) {
          char error[200];
          ERR_error_string_n(ERR_get_error(), error, 200);
          LOG_ERROR("%s", error);
          return;
      }
      if(err == SSL_ERROR_SYSCALL)
      {
          printf("%3d %s\n", errno, strerror(errno));
          return;
      }
  }*/
}

int dtls_transport_validate(char *buf) {

  if(buf == NULL)
    return 0;

  return ((*buf >= 19) && (*buf <= 64));
}


void dtls_transport_incomming_msg(DtlsTransport *dtls_transport, char *buf, int len) {

  if(dtls_transport->srtp_init_done)
    return;

  int written = BIO_write(dtls_transport->read_bio, buf, len);
  if(written != len) {
    LOG_ERROR();
  }
  else {

  }

  if(!dtls_transport->handshake_done)
    return;

/*  if(!dtls_transport->handshake_done)
  {
      dtls_transport_do_handshake(dtls_transport);
      if(!dtls_transport->handshake_done)
      {
          return;
      }
  }*/

  char data[3000];
  memset(&data, 0, 3000);
  int read = SSL_read(dtls_transport->ssl, &data, 3000);
  if(read < 0) {
    unsigned long err = SSL_get_error(dtls_transport->ssl, read);
    if(err == SSL_ERROR_SSL) {
      char error[200];
      ERR_error_string_n(ERR_get_error(), error, 200);
      LOG_ERROR("%s", error);
    }
  }

  if(!SSL_is_init_finished(dtls_transport->ssl)) {
    return;
  }

  X509 *rcert = SSL_get_peer_certificate(dtls_transport->ssl);
  if(!rcert) {
    LOG_ERROR("%s", ERR_reason_error_string(ERR_get_error()));
  }
  else {
    unsigned int rsize;
    unsigned char rfingerprint[EVP_MAX_MD_SIZE];
    X509_digest(rcert, EVP_sha256(), (unsigned char *)rfingerprint, &rsize);
    char remote_fingerprint[160];
    char *rfp = (char *)&remote_fingerprint;
    X509_free(rcert);
    rcert = NULL;
    unsigned int i = 0;
    for(i = 0; i < rsize; i++) {
      g_snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
      rfp += 3;
    }
    *(rfp-1) = 0;

    LOG_INFO("Remote fingerprint %s", remote_fingerprint);
    LOG_INFO("Local fingerprint %s", dtls_transport->fingerprint);
  }

  memset(&dtls_transport->remote_policy, 0x0, sizeof(dtls_transport->remote_policy));
  memset(&dtls_transport->local_policy, 0x0, sizeof(dtls_transport->local_policy));
  unsigned char material[SRTP_MASTER_LENGTH*2];
  unsigned char *local_key, *local_salt, *remote_key, *remote_salt;

  if (!SSL_export_keying_material(dtls_transport->ssl, material,
   SRTP_MASTER_LENGTH*2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
    LOG_ERROR("Couldn't extract SRTP keying material(%s)", ERR_reason_error_string(ERR_get_error()));
  }

  /* Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2) */
  remote_key = material;
  local_key = remote_key + SRTP_MASTER_KEY_LENGTH;
  remote_salt = local_key + SRTP_MASTER_KEY_LENGTH;
  local_salt = remote_salt + SRTP_MASTER_SALT_LENGTH;
  srtp_crypto_policy_set_rtp_default(&(dtls_transport->remote_policy.rtp));
  srtp_crypto_policy_set_rtcp_default(&(dtls_transport->remote_policy.rtcp));
  dtls_transport->remote_policy.ssrc.type = ssrc_any_inbound;
  unsigned char remote_policy_key[SRTP_MASTER_LENGTH];
  dtls_transport->remote_policy.key = (unsigned char *)&remote_policy_key;
  memcpy(dtls_transport->remote_policy.key, remote_key, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_transport->remote_policy.key + SRTP_MASTER_KEY_LENGTH, remote_salt, SRTP_MASTER_SALT_LENGTH);
  dtls_transport->remote_policy.next = NULL;
  srtp_crypto_policy_set_rtp_default(&(dtls_transport->local_policy.rtp));
  srtp_crypto_policy_set_rtcp_default(&(dtls_transport->local_policy.rtcp));
  dtls_transport->local_policy.ssrc.type = ssrc_any_outbound;
  unsigned char local_policy_key[SRTP_MASTER_LENGTH];
  dtls_transport->local_policy.key = (unsigned char *)&local_policy_key;
  memcpy(dtls_transport->local_policy.key, local_key, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_transport->local_policy.key + SRTP_MASTER_KEY_LENGTH, local_salt, SRTP_MASTER_SALT_LENGTH);
  dtls_transport->local_policy.next = NULL;

  srtp_err_status_t res = srtp_create(&dtls_transport->srtp_in, &dtls_transport->remote_policy);
  if(res != srtp_err_status_ok) {
    LOG_ERROR("Error creating inbound SRTP session for component");
  }
  LOG_INFO("Created inbound SRTP session");

  res = srtp_create(&(dtls_transport->srtp_out), &(dtls_transport->local_policy));
  if(res != srtp_err_status_ok) {
    LOG_ERROR("Error creating outbound SRTP session");
  }
  LOG_INFO("Created outbound SRTP session");
  dtls_transport->srtp_init_done = TRUE;

}

void dtls_transport_decrypt_rtp_packet(DtlsTransport *dtls_transport, uint8_t *packet, int *bytes)
{
    if(dtls_transport->srtp_in && packet && bytes)
    {
        srtp_unprotect(dtls_transport->srtp_in, packet, bytes);
    }
}


void dtls_transport_encrypt_rtp_packet(DtlsTransport *dtls_transport, uint8_t *packet, int *bytes)
{
    if(dtls_transport->srtp_out)
    {
        srtp_protect(dtls_transport->srtp_out, packet, bytes);
    }
}

void dtls_transport_encrypt_rctp_packet(DtlsTransport *dtls_transport, uint8_t *packet, int *bytes) {

  srtp_protect_rtcp(dtls_transport->srtp_out, packet, bytes);
}

const char* dtls_transport_get_fingerprint(DtlsTransport *dtls_transport) {

  return dtls_transport->fingerprint;
}
