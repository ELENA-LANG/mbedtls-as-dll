//---------------------------------------------------------------------------
 //		E L E N A   P r o j e c t:  Defines the entry point for the DLL application.
 //
 //                                             (C)2025-2026, by Aleksey Rakov
 //---------------------------------------------------------------------------

#include <windows.h>
#include "mbedtls_api.h"
#include "cert.h"

using namespace elena_mbedtls;

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

// =========================== Environment layer ================================================================

EXTERN_DLL_EXPORT Environment* mbedtls_startup()
{
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
   return ctx->crt_parse(TEST_CA_CRT_RSA_SHA256_PEM);
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

