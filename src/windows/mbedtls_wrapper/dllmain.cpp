/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

 //---------------------------------------------------------------------------
 //		E L E N A   P r o j e c t:  DLL Wrapper around Mbed TLS routines
 //
 //                                             (C)2025, by Aleksey Rakov
 //---------------------------------------------------------------------------


// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"

#include "mbedtls/ssl_cache.h"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

struct Environment
{
   mbedtls_ssl_config* conf;
   mbedtls_ctr_drbg_context* ctr_drbg;
   mbedtls_entropy_context* entropy;

   void init()
   {
      printf("mbedtls_ctr_drbg_init\n");
      printf("mbedtls_ssl_config_init\n");
      printf("mbedtls_entropy_init\n");

      mbedtls_ctr_drbg_init(ctr_drbg);
      mbedtls_ssl_config_init(conf);
      mbedtls_entropy_init(entropy);
   }

   void close()
   {
      printf("mbedtls_ctr_drbg_free\n");
      printf("mbedtls_ssl_config_free\n");
      printf("mbedtls_entropy_free\n");

      mbedtls_ctr_drbg_free(ctr_drbg);
      mbedtls_ssl_config_free(conf);
      mbedtls_entropy_free(entropy);
   }

   Environment()
   {
      ctr_drbg = new mbedtls_ctr_drbg_context();
      conf = new mbedtls_ssl_config();
      entropy = new mbedtls_entropy_context();
   }

   virtual ~Environment()
   {
      delete ctr_drbg;
      delete conf;
      delete entropy;
   }
};

struct Context
{
   mbedtls_net_context*        server_fd;
   mbedtls_ssl_context*        ssl;

   void init()
   {
      printf("mbedtls_net_init\n");
      printf("mbedtls_ssl_init\n");

      mbedtls_net_init(server_fd);
      mbedtls_ssl_init(ssl);
   }

   void close()
   {
      printf("mbedtls_net_free\n");
      printf("mbedtls_ssl_free\n");

      mbedtls_net_free(server_fd);
      mbedtls_ssl_free(ssl);
   }

   Context()
   {
      server_fd = new mbedtls_net_context();
      ssl = new mbedtls_ssl_context();
   }
   virtual ~Context()
   {
      delete server_fd;
      delete ssl;
   }
};

struct ServerContext
{
   mbedtls_ssl_cache_context* cache;
   mbedtls_x509_crt*          srvcert;
   mbedtls_x509_crt*          cachain;

   void init()
   {
      mbedtls_ssl_cache_init(cache);
      mbedtls_x509_crt_init(srvcert);
      mbedtls_x509_crt_init(cachain);
   }

   void close()
   {
      mbedtls_x509_crt_free(srvcert);
      mbedtls_x509_crt_free(cachain);
      mbedtls_ssl_cache_free(cache);
   }

   ServerContext()
   {
      cache = new mbedtls_ssl_cache_context();
      srvcert = new mbedtls_x509_crt();
      cachain = new mbedtls_x509_crt();
   }
   virtual ~ServerContext()
   {
      delete cachain;
      delete srvcert;
      delete cache;
   }
};

// =========================== Environment layer ================================================================

static Environment* env = nullptr;
static int env_counter = 0;

EXTERN_DLL_EXPORT void mbedtls_startup()
{
   if (!env) {
      env_counter = 1;

      env = new Environment();

      env->init();
   }
   else env_counter++;
}

EXTERN_DLL_EXPORT void mbedtls_shutdown()
{
   if (env_counter <= 0)
      return;

   env_counter--;
   if (!env_counter) {
      env->close();

      delete env;

      env = nullptr;
   }
}

EXTERN_DLL_EXPORT int mbedtls_drbg_seed_def(const unsigned char* custom, size_t len)
{
   printf("mbedtls_ctr_drbg_seed\n");

   return mbedtls_ctr_drbg_seed(env->ctr_drbg, mbedtls_entropy_func, env->entropy, custom, len);
}

EXTERN_DLL_EXPORT int mbedtls_config_ssl(int endpoint, int transport, int preset)
{
   printf("mbedtls_ssl_config_defaults\n");

   return mbedtls_ssl_config_defaults(env->conf, endpoint, transport, preset);
}

EXTERN_DLL_EXPORT void mbedtls_client_setup(int authmode)
{
   printf("mbedtls_ssl_conf_authmode\n");
   printf("mbedtls_ssl_conf_rng\n");

   mbedtls_ssl_conf_authmode(env->conf, authmode);

   mbedtls_ssl_conf_rng(env->conf, mbedtls_ctr_drbg_random, env->ctr_drbg);
}

// =========================== Server Context layer ================================================================

EXTERN_DLL_EXPORT ServerContext* mbedtls_new_server_context()
{
   mbedtls_startup();

   auto context = new ServerContext();
   context->init();

   return context;
}

EXTERN_DLL_EXPORT void mbedtls_delete_server_context(ServerContext* context)
{
   context->close();

   delete context;

   mbedtls_shutdown();
}

// =========================== Client Context layer ================================================================

EXTERN_DLL_EXPORT Context* mbedtls_new_context()
{
   mbedtls_startup();

   auto context = new Context();

   context->init();

   return context;
}

EXTERN_DLL_EXPORT void mbedtls_delete_context(Context* context)
{
   context->close();

   delete context;

   mbedtls_shutdown();
}

EXTERN_DLL_EXPORT void mbedtls_free_context(Context* context)
{
   context->close();
}

EXTERN_DLL_EXPORT int mbedtls_context_net_connect(Context* context, const char* host, const char* port, int proto)
{
   printf("mbedtls_net_connect\n");

   return mbedtls_net_connect(context->server_fd, host, port, proto);
}

EXTERN_DLL_EXPORT int mbedtls_context_setup(Context* context)
{
   printf("mbedtls_ssl_setup\n");

   return mbedtls_ssl_setup(context->ssl, env->conf);
}

EXTERN_DLL_EXPORT int mbedtls_context_ssl_set_hostname(Context* context, const char* hostname)
{
   printf("mbedtls_ssl_set_hostname\n");
   return mbedtls_ssl_set_hostname(context->ssl, hostname);
}

EXTERN_DLL_EXPORT void mbedtls_context_ssl_set_bio_def(Context* context)
{
   printf("mbedtls_ssl_set_bio\n");
   mbedtls_ssl_set_bio(context->ssl, context->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
}

EXTERN_DLL_EXPORT int mbedtls_context_read(Context* context, unsigned char* buf, size_t len)
{
   return mbedtls_ssl_read(context->ssl, buf, len);
}

EXTERN_DLL_EXPORT int mbedtls_context_write(Context* context, const unsigned char* buf, size_t len)
{
   printf("mbedtls_ssl_write\n");
   return mbedtls_ssl_write(context->ssl, buf, len);
}

EXTERN_DLL_EXPORT int mbedtls_socket_data_available(Context* context)
{
   int retVal = mbedtls_net_poll(context->server_fd, MBEDTLS_NET_POLL_READ, 10);

   return retVal == MBEDTLS_NET_POLL_READ;
}

// ==================== Direct functionality ===========================

EXTERN_DLL_EXPORT void net_init(mbedtls_net_context* ctx)
{
   mbedtls_net_init(ctx);
}

EXTERN_DLL_EXPORT void ssl_init(mbedtls_ssl_context* ssl)
{
   mbedtls_ssl_init(ssl);
}

EXTERN_DLL_EXPORT void ssl_config_init(mbedtls_ssl_config* conf)
{
   mbedtls_ssl_config_init(conf);
}

EXTERN_DLL_EXPORT void ctr_drbg_init(mbedtls_ctr_drbg_context* ctx)
{
   mbedtls_ctr_drbg_init(ctx);
}

EXTERN_DLL_EXPORT void entropy_init(mbedtls_entropy_context* ctx)
{
   mbedtls_entropy_init(ctx);
}

EXTERN_DLL_EXPORT int ctr_drbg_seed_def(mbedtls_ctr_drbg_context* ctx,
   void* p_entropy,
   const unsigned char* custom,
   size_t len)
{
   return mbedtls_ctr_drbg_seed(ctx, mbedtls_entropy_func, p_entropy, custom, len);
}

EXTERN_DLL_EXPORT int net_connect(mbedtls_net_context* ctx, const char* host, const char* port, int proto)
{
   return mbedtls_net_connect(ctx, host, port, proto);
}

EXTERN_DLL_EXPORT int ssl_config_defaults(mbedtls_ssl_config* conf,
   int endpoint, int transport, int preset)
{
   return mbedtls_ssl_config_defaults(conf, endpoint, transport, preset);
}

EXTERN_DLL_EXPORT void ssl_conf_authmode(mbedtls_ssl_config* conf, int authmode)
{
   mbedtls_ssl_conf_authmode(conf, authmode);
}

EXTERN_DLL_EXPORT void ssl_conf_rng_def(mbedtls_ssl_config* conf,
   void* p_rng)
{
   mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, p_rng);
}

EXTERN_DLL_EXPORT int ssl_setup(mbedtls_ssl_context* ssl,
   const mbedtls_ssl_config* conf)
{
   return mbedtls_ssl_setup(ssl, conf);
}

EXTERN_DLL_EXPORT int ssl_set_hostname(mbedtls_ssl_context* ssl, const char* hostname)
{
   return mbedtls_ssl_set_hostname(ssl, hostname);
}

EXTERN_DLL_EXPORT void ssl_set_bio_def(mbedtls_ssl_context* ssl,
   void* p_bio)
{
   mbedtls_ssl_set_bio(ssl, p_bio, mbedtls_net_send, mbedtls_net_recv, NULL);
}

EXTERN_DLL_EXPORT int ssl_write(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len)
{
   return mbedtls_ssl_write(ssl, buf, len);
}

EXTERN_DLL_EXPORT const mbedtls_x509_crt* ssl_get_peer_cert(const mbedtls_ssl_context* ssl)
{
   return mbedtls_ssl_get_peer_cert(ssl);
}

EXTERN_DLL_EXPORT int x509_crt_info(char* buf, size_t size, const char* prefix,
   const mbedtls_x509_crt* crt)
{
   return mbedtls_x509_crt_info(buf, size, prefix, crt);
}

EXTERN_DLL_EXPORT uint32_t ssl_get_verify_result(const mbedtls_ssl_context* ssl)
{
   return mbedtls_ssl_get_verify_result(ssl);
}

EXTERN_DLL_EXPORT int x509_crt_verify_info(char* buf, size_t size, const char* prefix,
   uint32_t flags)
{
   return mbedtls_x509_crt_verify_info(buf, size, prefix, flags);
}

EXTERN_DLL_EXPORT int ssl_read(mbedtls_ssl_context* ssl, unsigned char* buf, size_t len)
{
   return mbedtls_ssl_read(ssl, buf, len);
}

EXTERN_DLL_EXPORT void net_free(mbedtls_net_context* ctx)
{
   mbedtls_net_free(ctx);
}

EXTERN_DLL_EXPORT void ssl_free(mbedtls_ssl_context* ssl)
{
   mbedtls_ssl_free(ssl);
}

EXTERN_DLL_EXPORT void ssl_config_free(mbedtls_ssl_config* conf)
{
   mbedtls_ssl_config_free(conf);
}

EXTERN_DLL_EXPORT void ctr_drbg_free(mbedtls_ctr_drbg_context* ctx)
{
   mbedtls_ctr_drbg_free(ctx);
}

EXTERN_DLL_EXPORT void entropy_free(mbedtls_entropy_context* ctx)
{
   mbedtls_entropy_free(ctx);
}

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

