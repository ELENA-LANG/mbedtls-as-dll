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
   //getchar();

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
   return env->config(endpoint, transport, preset);
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
   auto context = new Context(true);

   context->init();

   return context;
}

EXTERN_DLL_EXPORT Context* mbedtls_new_remote_context()
{
   auto context = new Context(false);

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
   auto context = new ServerContext();
   context->init();

   env->server = context;
}

EXTERN_DLL_EXPORT int mbedtls_init_srvcert(Environment* env)
{
   if (env->server) {
      int ret = env->server->parse_srvcert(TEST_SRV_CRT, sizeof(TEST_SRV_CRT));
      if (!ret)
         ret = env->server->parse_srvcert(TEST_CA_CRT, sizeof(TEST_CA_CRT));

      return ret;
   }
      return env->server->parse_srvcert(TEST_SRV_CRT, sizeof(TEST_SRV_CRT));

   return -1;
}

EXTERN_DLL_EXPORT int mbedtls_init_srv_key(Environment* env)
{
   if (env->server) {
      return env->server->parse_key(TEST_SRV_KEY, sizeof(TEST_SRV_KEY));
   }

   return -1;
}

EXTERN_DLL_EXPORT int mbedtls_servercontext_setup(Environment* env)
{
   if (env->server) {
      env->initCache();

      return env->config_own_cert();
   }

   return -1;
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
   return context->net_bind(portStr);
}

EXTERN_DLL_EXPORT int mbedtls_accept_net_context(NetContext* listener, NetContext* client)
{
   return listener->accept(client);
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

