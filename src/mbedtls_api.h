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
 //                                             (C)2025-2026, by Aleksey Rakov
 //---------------------------------------------------------------------------

#ifndef MBEDTLS_WRAPPER_H
#define MBEDTLS_WRAPPER_H


#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "mbedtls/mbedtls_config.h"

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/private/entropy.h"
#include "mbedtls/private/ctr_drbg.h"
#include "mbedtls/error.h"
#include "test/certs.h"

#include "mbedtls/ssl_cache.h"

#include "mbedtls/x509.h"

namespace elena_mbedtls
{
   struct ServerContext
   {
      mbedtls_ssl_cache_context* cache;
      mbedtls_x509_crt* srvcert;
      mbedtls_x509_crt* cachain;
      mbedtls_pk_context* pkey;

      void init()
      {
         mbedtls_ssl_cache_init(cache);
         mbedtls_x509_crt_init(srvcert);
         mbedtls_x509_crt_init(cachain);
         mbedtls_pk_init(pkey);
      }

      void close()
      {
         mbedtls_x509_crt_free(srvcert);
         mbedtls_x509_crt_free(cachain);
         mbedtls_ssl_cache_free(cache);
         mbedtls_pk_free(pkey);
      }

      ServerContext()
      {
         cache = new mbedtls_ssl_cache_context();
         srvcert = new mbedtls_x509_crt();
         cachain = new mbedtls_x509_crt();
         pkey = new mbedtls_pk_context();
      }
      virtual ~ServerContext()
      {
         delete cachain;
         delete srvcert;
         delete cache;
         delete pkey;
      }
   };

   struct Environment
   {
      mbedtls_ssl_config* conf;
      mbedtls_ctr_drbg_context* ctr_drbg;
      mbedtls_entropy_context* entropy;

      ServerContext* server;

      void init()
      {
         mbedtls_ctr_drbg_init(ctr_drbg);
         mbedtls_ssl_config_init(conf);
         mbedtls_entropy_init(entropy);
      }

      void client_setup(int authmode)
      {
         mbedtls_ssl_conf_authmode(conf, authmode);
      }

      void close()
      {
         if (server)
            server->close();

         mbedtls_ctr_drbg_free(ctr_drbg);
         mbedtls_ssl_config_free(conf);
         mbedtls_entropy_free(entropy);
      }

      Environment()
      {
         ctr_drbg = new mbedtls_ctr_drbg_context();
         conf = new mbedtls_ssl_config();
         entropy = new mbedtls_entropy_context();
         server = nullptr;
      }

      virtual ~Environment()
      {
         if (server)
            delete server;

         delete ctr_drbg;
         delete conf;
         delete entropy;
      }

      static int psa_init()
      {
         return psa_crypto_init();
      }

      int drbg_seed(const unsigned char* custom, size_t len)
      {
         return mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, custom, len);
      }
   };

   struct NetContext
   {
      mbedtls_net_context* net_fd;

      virtual void init()
      {
         mbedtls_net_init(net_fd);
      }

      virtual void close()
      {
         mbedtls_net_free(net_fd);
      }

      NetContext()
      {
         net_fd = new mbedtls_net_context();
      }

      virtual ~NetContext()
      {
         delete net_fd;
      }
   };

   struct Context : public NetContext
   {
      mbedtls_ssl_context* ssl;
      mbedtls_x509_crt*    cacert;

      void init() override
      {
         NetContext::init();
         mbedtls_ssl_init(ssl);
         mbedtls_x509_crt_init(cacert);
      }

      int connect(const char* host, const char* port, int proto)
      {
         return mbedtls_net_connect(net_fd, host, port, proto);
      }

      int crt_parse(const char* cas_pem, size_t cas_pem_len)
      {
         return mbedtls_x509_crt_parse(cacert, (const unsigned char*)cas_pem,
            cas_pem_len);
      }

      int setup(Environment* env)
      {
         mbedtls_ssl_conf_ca_chain(env->conf, cacert, NULL);

         return mbedtls_ssl_setup(ssl, env->conf);
      }

      int set_hostname(const char* hostname)
      {
         return mbedtls_ssl_set_hostname(ssl, hostname);
      }

      void set_bio()
      {
         mbedtls_ssl_set_bio(ssl, net_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
      }

      int handshake()
      {
         int ret;
         while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
               return ret;
            }
         }

         return 0;
      }

      int verify()
      {
         uint32_t flags = 0;
         if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
//#if !defined(MBEDTLS_X509_REMOVE_INFO)
//            char vrfy_buf[512];
//            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
//#endif
            return flags;

         }
         else return 0;
      }

      int read(unsigned char* buf, size_t len)
      {
         return mbedtls_ssl_read(ssl, buf, len);
      }

      int write(const unsigned char* buf, size_t len)
      {
         return mbedtls_ssl_write(ssl, buf, len);
      }

      int data_available()
      {
         int retVal = mbedtls_net_poll(net_fd, MBEDTLS_NET_POLL_READ, 10);

         return retVal == MBEDTLS_NET_POLL_READ;
      }

      void close() override
      {
         NetContext::close();
         mbedtls_ssl_free(ssl);
         mbedtls_x509_crt_free(cacert);
      }

      Context()
         : NetContext()
      {
         ssl = new mbedtls_ssl_context();
         cacert = new mbedtls_x509_crt();
      }
      virtual ~Context()
      {
         delete ssl;
         delete cacert;
      }
   };
}

#endif // MBEDTLS_WRAPPER_H