It is a DLL wrapper around MbedTLS static library to be used in ELENA API


# Compiling

The project is compiled with Visual Studio C++

It is only a wrapper around Mbed TLS, so we need to download and import it into your local folder

## Downloading and compiling Mbed TLS

You can download it from GitHub - https://github.com/Mbed-TLS

When you can compile it using CMake toolset for Visual Studio C++

The expected output path for x86 is <mbedtls-as-dll-root-path>\out\build\x86-Debug\ 

## Importing

You can import all required files using a script

   cd <mbedtls-as-dll-root-path>\src
   scripts\import.bat <Mbed-TLS-root-path>
