-- |
--
-- Module: Sel
-- Description: Cryptography for the casual user
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
--
-- Sel is the library for casual users by the [Haskell Cryptography Group](https://haskell-cryptography.org).
--
-- It builds on [Libsodium](https://doc.libsodium.org), a reliable and audited library for common operations.
--
-- ⚠️ Important note: if you want to use any of this code in an executable, ensure that you use 'secureMain' or 'secureMainWithError' in your @main@ function __before__ you call any functions from this library. Failing to do so will cause problems. For libraries, this is not necessary.
--
-- +--+----------------------------------------------------------------------+--------------------------------+
-- |  |                              Purpose                                 | Module                         |
-- +==+======================================================================+================================+
-- |  |                              __Hashing__                             |                                |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | Hash passwords                                                       | "Sel.Hashing.Password"         |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | Verify the integrity of files and hash large data                    | "Sel.Hashing"                  |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | Hash tables, bloom filters, fast integrity checking of short input   | "Sel.Hashing.Short"            |
-- +--+----------------------------------------------------------------------+--------------------------------+
-- |  | __Secret key / symmetric cryptography__                              |                                |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | Authenticate a message with a secret key                             | "Sel.SecretKey.Authentication" |
-- +--+----------------------------------------------------------------------+--------------------------------+
-- |  | Encrypt and sign data with a secret key                              | "Sel.SecretKey.Cipher"         |
-- +--+----------------------------------------------------------------------+--------------------------------+
-- |  | __Public and Secret key / asymmetric cryptography__                  |                                |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | Sign and encrypt with my secret key and my recipient's public key    | "Sel.PublicKey.Cipher"         |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | Sign and encrypt an anonymous message with my recipient's public key | "Sel.PublicKey.Seal"           |
-- +--+----------------------------------------------------------------------+--------------------------------+
-- |  | Sign with a secret key and distribute my public key                  | "Sel.PublicKey.Signature"      |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | __HMAC message authentication__                                      |                                |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | HMAC-256                                                             | "Sel.HMAC.SHA256"              |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | HMAC-512                                                             | "Sel.HMAC.SHA512"              |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | HMAC-512-256                                                         | "Sel.HMAC.SHA512_256"          |
-- +--+----------------------------------------------------------------------+--------------------------------+
-- |  | __Legacy SHA2 constructs__                                           |                                |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | SHA-256                                                              | "Sel.Hashing.SHA256"           |
-- |  +----------------------------------------------------------------------+--------------------------------+
-- |  | SHA-512                                                              | "Sel.Hashing.SHA512"           |
-- +--+----------------------------------------------------------------------+--------------------------------+

module Sel
  ( secureMain
  , secureMainWithError
  ) where

import LibSodium.Bindings.Main (secureMain, secureMainWithError)
