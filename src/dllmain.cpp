//---------------------------------------------------------------------------
 //		E L E N A   P r o j e c t:  Defines the entry point for the DLL application.
 //
 //                                             (C)2025-2026, by Aleksey Rakov
 //---------------------------------------------------------------------------

#include <windows.h>
#include "mbedtls_api.h"
#include "cert.h"

#include "test/certs.h"

using namespace elena_mbedtls;

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

// =========================== Environment layer ================================================================

EXTERN_DLL_EXPORT Environment* mbedtls_startup()
{
   getchar();


// =====================================

//   int ret = 1, len;
//   int exit_code = 0;
//   mbedtls_net_context server_fd;
//   uint32_t flags;
//   unsigned char buf[1024];
//   const char* pers = "ssl_client1";
//
//   mbedtls_entropy_context entropy;
//   mbedtls_ctr_drbg_context ctr_drbg;
//   mbedtls_ssl_context ssl;
//   mbedtls_ssl_config conf;
//   mbedtls_x509_crt cacert;
//
////
////#if defined(MBEDTLS_DEBUG_C)
////   mbedtls_debug_set_threshold(DEBUG_LEVEL);
////#endif
//
//   /*
//    * 0. Initialize the RNG and the session data
//    */
//   mbedtls_net_init(&server_fd);
//   mbedtls_ssl_init(&ssl);
//   mbedtls_ssl_config_init(&conf);
//   mbedtls_x509_crt_init(&cacert);
//   mbedtls_ctr_drbg_init(&ctr_drbg);
//   mbedtls_entropy_init(&entropy);
//
//   psa_status_t status = psa_crypto_init();
//   if (status != PSA_SUCCESS) {
//      printf("Failed to initialize PSA Crypto implementation: %d\n",
//         (int)status);
//      //goto exit;
//   }
//
//   mbedtls_printf("\n  . Seeding the random number generator...");
//   fflush(stdout);
//
//
//   if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
//      (const unsigned char*)pers,
//      strlen(pers))) != 0) {
//      printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
//      //goto exit;
//   }
//
//   mbedtls_printf(" ok\n");
//
//   mbedtls_printf("  . Loading the CA root certificate ...");
//   fflush(stdout);
//
//   ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)TEST_CA_CRT,
//      sizeof(TEST_CA_CRT));
//   if (ret < 0) {
//      mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
//         (unsigned int)-ret);
//      //goto exit;
//   }
//
//   mbedtls_printf(" ok (%d skipped)\n", ret);
// =====================================

   Environment* env = new Environment();

   env->init();

   return env;
}

EXTERN_DLL_EXPORT int mbedtls_drbg_seed_def(Environment* env, const unsigned char* custom, size_t len)
{
   return env->drbg_seed(custom, len);
}

EXTERN_DLL_EXPORT int mbedtls_config_ssl(Environment* env, int endpoint, int transport, int preset)
{
   return mbedtls_ssl_config_defaults(env->conf, endpoint, transport, preset);
}

EXTERN_DLL_EXPORT int mbedtls_init_psa()
{
   return Environment::psa_init();
}

EXTERN_DLL_EXPORT void mbedtls_shutdown(Environment* env)
{
   env->close();

   delete env;
}

// =========================== Client Context layer ================================================================

EXTERN_DLL_EXPORT Context* mbedtls_new_context()
{
   auto context = new Context();

   context->init();

   return context;
}

EXTERN_DLL_EXPORT int mbedtls_cert_parse(Context* ctx)
{
   return ctx->crt_parse(TEST_CA_CRT, sizeof(TEST_CA_CRT));
}

EXTERN_DLL_EXPORT void mbedtls_client_setup(Environment* env, int authmode)
{
   env->client_setup(authmode);   
}

EXTERN_DLL_EXPORT int mbedtls_context_setup(Environment* env, Context* context)
{
   return context->setup(env);
}

EXTERN_DLL_EXPORT int mbedtls_context_net_connect(Context* context, const char* host, const char* port, int proto)
{
   return context->connect(host, port, proto);
}

EXTERN_DLL_EXPORT int mbedtls_context_ssl_set_hostname(Context* context, const char* hostname)
{
   return context->set_hostname(hostname);
}

EXTERN_DLL_EXPORT void mbedtls_context_ssl_set_bio_def(Context* context)
{
   context->set_bio();
}

EXTERN_DLL_EXPORT int mbedtls_handshake(Context* context)
{
   return context->handshake();
}

EXTERN_DLL_EXPORT int mbedtls_verify(Context* context)
{
   return context->verify();
}

EXTERN_DLL_EXPORT int mbedtls_context_read(Context* context, unsigned char* buf, size_t len)
{
   return context->read(buf, len);
}

EXTERN_DLL_EXPORT int mbedtls_context_write(Context* context, const unsigned char* buf, size_t len)
{
   return context->write(buf, len);
}

EXTERN_DLL_EXPORT int mbedtls_socket_data_available(Context* context)
{
   return context->data_available();
}

EXTERN_DLL_EXPORT void mbedtls_delete_context(Context* context)
{
   context->close();

   delete context;
}

EXTERN_DLL_EXPORT void mbedtls_free_context(Context* context)
{
   context->close();
}

// =========================== Server Context layer ================================================================

EXTERN_DLL_EXPORT void mbedtls_new_server_context(Environment* env)
{
/*   auto context = new ServerContext();
   context->init();

   env->server = context;*/
}

EXTERN_DLL_EXPORT int mbedtls_init_srvcert(Environment* env)
{
   //return mbedtls_x509_crt_parse(env->server->srvcert, (const unsigned char*)mbedtls_test_srv_crt,
   //   mbedtls_test_srv_crt_len);

   return 0;
}

EXTERN_DLL_EXPORT int mbedtls_init_cachain(Environment* env)
{
//   return mbedtls_x509_crt_parse(env->server->cachain, (const unsigned char*)mbedtls_test_cas_pem,
//      mbedtls_test_cas_pem_len);

   return 0;
}

EXTERN_DLL_EXPORT int mbedtls_init_srv_key(Environment* env)
{
//   return mbedtls_pk_parse_key(env->server->pkey, (const unsigned char*)mbedtls_test_srv_key,
//      mbedtls_test_srv_key_len, NULL, 0, mbedtls_ctr_drbg_random, env->ctr_drbg);

   return 0;
}

EXTERN_DLL_EXPORT int mbedtls_servercontext_setup(Environment* env)
{
   //mbedtls_ssl_conf_session_cache(env->conf, env->server->cache,
   //   mbedtls_ssl_cache_get,
   //   mbedtls_ssl_cache_set);

   //mbedtls_ssl_conf_ca_chain(env->conf, env->server->cachain, NULL);

   //return mbedtls_ssl_conf_own_cert(env->conf, env->server->srvcert, env->server->pkey);

   return 0;
}

// =========================== Net Context layer ================================================================

EXTERN_DLL_EXPORT NetContext* mbedtls_new_net_context()
{
   auto context = new NetContext();

   context->init();

   return context;
}

EXTERN_DLL_EXPORT int mbedtls_bind_net_context(NetContext* context, const char* portStr)
{
   //return mbedtls_net_bind(context->net_fd, NULL, portStr, MBEDTLS_NET_PROTO_TCP);

   return 0;
}

EXTERN_DLL_EXPORT int mbedtls_accept_net_context(NetContext* listener, NetContext* client)
{
   //return mbedtls_net_accept(listener->net_fd, client->net_fd, NULL, 0, NULL);

   return 0;
}

EXTERN_DLL_EXPORT void mbedtls_delete_net_context(NetContext* context)
{
   context->close();

   delete context;
}

// =========================== DllMain ================================================================

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

