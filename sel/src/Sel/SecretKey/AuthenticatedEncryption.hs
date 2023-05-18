{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.SecretKey.AuthenticatedEncryption
-- Description: Authenticated Encryption with Poly1305 MAC and XSalsa20
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.SecretKey.AuthenticatedEncryption
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage
    SecretKey
  , newSecretKey
  , Nonce
  , Hash
  , encrypt
  , decrypt
  ) where

import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Unsafe as BS
import Foreign (ForeignPtr)
import qualified Foreign
import Foreign.C (CChar, CUChar, CULLong)
import GHC.IO.Handle.Text (memcpy)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Control.Monad (void)
import Data.Word (Word8)
import LibSodium.Bindings.Random (randombytesBuf)
import LibSodium.Bindings.Secretbox (cryptoSecretboxEasy, cryptoSecretboxKeyBytes, cryptoSecretboxKeygen, cryptoSecretboxMACBytes, cryptoSecretboxNonceBytes, cryptoSecretboxOpenEasy)
import Sel.Internal

-- $introduction
-- Authenticated Encryption is the action of encrypting a message using a secret key
-- and a one-time cryptographic number ("nonce"). The resulting ciphertext is accompanied
-- by an authentication tag.
--
-- Encryption is done with the XSalsa20 stream cipher and authentication is done with the
-- Poly1305 MAC hash.

-- $usage
--
-- > import qualified Sel.SecretKey.AuthenticatedEncryption as AuthenticatedEncryption
-- >
-- > main = do
-- >   -- We get the secretKey from the other party or with 'newSecretKey'.
-- >   -- We get the nonce from the other party with the message, or with 'encrypt' and our own message.
-- >   -- Do not reuse a nonce with the same secret key!
-- >   (nonce, encryptedMessage) <- AuthenticatedEncryption.encrypt "hello hello" secretKey
-- >   let result = AuthenticatedEncryption.decrypt encryptedMessage secretKey nonce
-- >   print result
-- >   -- "Just \"hello hello\""

-- | A secret key of size 'cryptoSecretboxKeyBytes'.
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq SecretKey where
  (SecretKey hk1) == (SecretKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrEq hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoSecretboxKeyBytes

-- | A random number that must only be used once per exchanged message.
-- It does not have to be confidential.
-- It is of size 'cryptoSecretboxNonceBytes'.
--
-- @since 0.0.1.0
newtype Nonce = Nonce (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Nonce where
  (Nonce hk1) == (Nonce hk2) =
    unsafeDupablePerformIO $
      foreignPtrEq hk1 hk2 cryptoSecretboxKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord Nonce where
  compare (Nonce hk1) (Nonce hk2) =
    unsafeDupablePerformIO $
      foreignPtrOrd hk1 hk2 cryptoSecretboxKeyBytes

-- | Generate a new random secret key.
--
-- @since 0.0.1.0
newSecretKey :: IO SecretKey
newSecretKey = do
  fPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretboxKeyBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    cryptoSecretboxKeygen ptr
  pure $ SecretKey fPtr

-- | Generate a new random nonce.
-- Only use it once per exchanged message.
--
-- Do not use this outside of hash creation!
newNonce :: IO Nonce
newNonce = do
  (fPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoSecretboxNonceBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    randombytesBuf (Foreign.castPtr @CUChar @Word8 ptr) cryptoSecretboxNonceBytes
  pure $ Nonce fPtr

-- | A ciphertext consisting of an encrypted message and an authentication tag.
--
-- @since 0.0.1.0
data Hash = Hash
  { messageLength :: CULLong
  , hashForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq Hash where
  (Hash messageLength1 hk1) == (Hash messageLength2 hk2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrEq hk1 hk2 (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
      pure $ (messageLength1 == messageLength2) && result1

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash messageLength1 hk1) (Hash messageLength2 hk2) =
    unsafeDupablePerformIO $ do
      result1 <- foreignPtrOrd hk1 hk2 (fromIntegral messageLength1 + cryptoSecretboxMACBytes)
      pure $ compare messageLength1 messageLength2 <> result1

-- | Create an authenticated hash from a message, a secret key that must remain secret, and a one-time cryptographic nonce
-- that must never be re-used with the same secret key to encrypt another message.
--
-- @since 0.0.1.0
encrypt
  :: StrictByteString
  -- ^ Message to encrypt.
  -> SecretKey
  -- ^ Secret key generated with 'newSecretKey'.
  -> IO (Nonce, Hash)
encrypt message (SecretKey secretKeyForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    (Nonce nonceForeignPtr) <- newNonce
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (cStringLen + fromIntegral cryptoSecretboxMACBytes)
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
        Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
          void $
            cryptoSecretboxEasy
              hashPtr
              (Foreign.castPtr @CChar @CUChar cString)
              (fromIntegral @Int @CULLong cStringLen)
              noncePtr
              secretKeyPtr
    let hash = Hash (fromIntegral @Int @CULLong cStringLen) hashForeignPtr
    pure (Nonce nonceForeignPtr, hash)

-- | Decrypt a hashed and authenticated message with the shared secret key and the one-time cryptographic nonce.
--
-- @since 0.0.1.0
decrypt
  :: Hash
  -- ^ Encrypted message you want to decrypt.
  -> SecretKey
  -- ^ Secret key used for encrypting the original message.
  -> Nonce
  -- ^ Nonce used for encrypting the original message.
  -> Maybe StrictByteString
decrypt Hash{messageLength, hashForeignPtr} (SecretKey secretKeyForeignPtr) (Nonce nonceForeignPtr) = unsafeDupablePerformIO $ do
  messagePtr <- Foreign.mallocBytes (fromIntegral @CULLong @Int messageLength)
  Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
    Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
      Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
        result <-
          cryptoSecretboxOpenEasy
            messagePtr
            hashPtr
            (messageLength + fromIntegral cryptoSecretboxMACBytes)
            noncePtr
            secretKeyPtr
        case result of
          (-1) -> pure Nothing
          _ -> do
            bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
            memcpy bsPtr (Foreign.castPtr messagePtr) (fromIntegral messageLength)
            Just <$> BS.unsafePackMallocCStringLen (Foreign.castPtr @CChar bsPtr, fromIntegral messageLength)
