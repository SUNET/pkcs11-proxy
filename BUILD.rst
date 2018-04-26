
Building PKCS11 Proxy
=====================

Make sure the relevant OpenSSL dev tools are installed.
For OS/X, just do :-
brew install openssl

cmake .

make

make install

On Linux RPM based systems, you can also create an RPM package via :-

make package
