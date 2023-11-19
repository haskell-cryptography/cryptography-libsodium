{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: LibSodium.Bindings.KeyExchange
-- Description: Direct bindings to the key exchange functions implemented in Libsodium
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module LibSodium.Bindings.KeyExchange
  ( -- * Introduction
    -- $introduction

    -- * Key Exchange

    -- ** Key generation
    cryptoKXKeyPair
  , cryptoKXSeedKeypair

    -- ** Client
  , cryptoKXClientSessionKeys

    -- ** Server
  , cryptoKXServerSessionKeys

    -- ** Constants
  , cryptoKXPublicKeyBytes
  , cryptoKXSecretKeyBytes
  , cryptoKXSeedBytes
  , cryptoKXSessionKeyBytes
  , cryptoKXPrimitive
  )
where

import Foreign (Ptr)
import Foreign.C (CChar, CInt (CInt), CSize (CSize), CUChar)

-- $introduction
--
-- The key exchange API allows two parties to securely compute a set of shared keys using their peer's public key, and
-- their own secret key.

-- | Create a new key pair.
--
-- This function takes pointers to two empty buffers that will hold (respectively) the public and secret keys.
--
-- /See:/ [crypto_kx_keypair()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_keypair"
  cryptoKXKeyPair
    :: Ptr CUChar
    -- ^ The buffer that will hold the public key, of size 'cryptoKXPublicKeyBytes'.
    -> Ptr CUChar
    -- ^ The buffer that will hold the secret key, of size 'cryptoKXSecretKeyBytes'.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error.

-- | Create a new key pair from a seed.
--
-- This function takes pointers to two empty buffers that will hold (respectively) the public and secret keys,
-- as well as the seed from which these keys will be derived.
--
-- /See:/ [crypto_kx_seed_keypair()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_seed_keypair"
  cryptoKXSeedKeypair
    :: Ptr CUChar
    -- ^ The buffer that will hold the public key, of size 'cryptoKXPublicKeyBytes'.
    -> Ptr CUChar
    -- ^ The buffer that will hold the secret key, of size 'cryptoKXSecretKeyBytes'.
    -> Ptr CUChar
    -- ^ The pointer to the seed from which the keys are derived. It is of size 'cryptoKXSeedBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error.

-- | Compute a pair of shared session keys (secret and public).
--
-- These session keys are computed using:
--
-- * The client's public key
-- * The client's secret key
-- * The server's public key
--
-- The shared secret key should be used by the client to receive data from the server, whereas the shared
-- public key should be used for data flowing to the server.
--
-- If only one session key is required, either the pointer to the shared secret key or the pointer
-- to the shared public key can be set to 'Foreign.nullPtr'.
--
-- /See:/ [crypto_kx_client_session_keys()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_client_session_keys"
  cryptoKXClientSessionKeys
    :: Ptr CUChar
    -- ^ A pointer to the buffer that will hold the shared secret key, of size 'cryptoKXSessionKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the buffer that will hold the shared public key, of size 'cryptoKXSessionKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the client's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the client's secret key, of size 'cryptoKXSecretKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the server's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error, such as when the server's public key is not acceptable.

--

-- | Compute a pair of shared session keys (secret and public).
--
-- These session keys are computed using:
--
-- * The server's public key
-- * The server's secret key
-- * The client's public key
--
-- The shared secret key should be used by the server to receive data from the client, whereas the shared
-- public key should be used for data flowing to the client.
--
-- If only one session key is required, either the pointer to the shared secret key or the pointer
-- to the shared public key can be set to 'Foreign.nullPtr'.
--
-- /See:/ [crypto_kx_server_session_keys()](https://doc.libsodium.org/key_exchange#usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h crypto_kx_server_session_keys"
  cryptoKXServerSessionKeys
    :: Ptr CUChar
    -- ^ A pointer to the buffer that will hold the shared secret key, of size 'cryptoKXSessionKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the buffer that will hold the shared public key, of size 'cryptoKXSessionKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the server's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the server's secret key, of size 'cryptoKXSecretKeyBytes' bytes.
    -> Ptr CUChar
    -- ^ A pointer to the client's public key, of size 'cryptoKXPublicKeyBytes' bytes.
    -> IO CInt
    -- ^ Returns 0 on success, -1 on error, such as when the server's public key is not acceptable.

-- | Size of the public key in bytes.
--
-- /See:/ [crypto_kx_PUBLICKEYBYTES](https://doc.libsodium.org/key_exchange#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_PUBLICKEYBYTES"
  cryptoKXPublicKeyBytes :: CSize

-- | Size of the secret key in bytes.
--
-- /See:/ [crypto_kx_SECRETKEYBYTES](https://doc.libsodium.org/key_exchange#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_SECRETKEYBYTES"
  cryptoKXSecretKeyBytes :: CSize

-- | Size of the seed in bytes.
--
-- /See:/ [crypto_kx_SEEDBYTES](https://doc.libsodium.org/key_exchange#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_SEEDBYTES"
  cryptoKXSeedBytes :: CSize

-- | Size of the session key in bytes.
--
-- /See:/ [crypto_kx_SESSIONKEYBYTES](https://doc.libsodium.org/key_exchange#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_SESSIONKEYBYTES"
  cryptoKXSessionKeyBytes :: CSize

-- | Primitive used by this module
--
-- /See:/ [crypto_kx_PRIMITIVE](https://doc.libsodium.org/key_exchange#constants)
--
-- @since 0.0.1.0
foreign import capi "sodium.h value crypto_kx_PRIMITIVE"
  cryptoKXPrimitive :: Ptr CChar
