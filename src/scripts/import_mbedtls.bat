REM NOTE : the script MUST be called from the root folder

xcopy %1\include\mbedtls\net_sockets.h  library\include\mbedtls\ /I /Y
xcopy %1\include\mbedtls\error.h library\include\mbedtls\ /I /Y
xcopy %1\include\mbedtls\mbedtls_config.h library\include\mbedtls\ /I /Y

xcopy %1\include\mbedtls\ssl.h  library\include\mbedtls\ /I /Y
xcopy %1\include\mbedtls\ssl_*.h  library\include\mbedtls\ /I /Y

xcopy %1\include\mbedtls\x509.h  library\include\mbedtls\ /I /Y
xcopy %1\include\mbedtls\x509_*.h  library\include\mbedtls\ /I /Y

xcopy %1\tf-psa-crypto\include\mbedtls\platform_util.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\platform_time.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\platform.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\pk.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\md.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\asn1.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\compat-3-crypto.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\psa_util.h library\include\mbedtls\ /I /Y
xcopy %1\tf-psa-crypto\include\mbedtls\asn1write.h library\include\mbedtls\ /I /Y

xcopy %1\tf-psa-crypto\include\tf-psa-crypto\build_info.h library\include\tf-psa-crypto\ /I /Y

xcopy %1\tf-psa-crypto\include\psa\crypto_*.h library\include\psa\ /I /Y 
xcopy %1\tf-psa-crypto\include\psa\crypto.h library\include\psa\ /I /Y 

xcopy %1\tf-psa-crypto\drivers\builtin\include\mbedtls\private_access.h library\include\mbedtls\ /I /Y

xcopy %1\tf-psa-crypto\drivers\builtin\include\mbedtls\private\*.h library\include\mbedtls\private\ /I /Y

xcopy %1\tf-psa-crypto\drivers\builtin\include\mbedtls\config_adjust_legacy_crypto.h library\include\mbedtls\ /I /Y

xcopy %1\tf-psa-crypto\include\tf-psa-crypto\build_info.h library\include\mbedtls\ /I /Y 

xcopy %1\tests\include\test\certs.h library\include\test\ /I /Y 

xcopy %1\out\build\x86-Debug\library\mbedtls.lib library\x86\ /I /Y 
xcopy %1\out\build\x86-Debug\library\mbedx509.lib library\x86\ /I /Y 
xcopy %1\out\build\x86-Debug\library\tfpsacrypto.lib library\x86\ /I /Y 




