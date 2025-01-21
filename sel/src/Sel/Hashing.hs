{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.Hashing
-- Description: Hashing with the BLAKE2b algorithm
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing
  ( -- ** Introduction
    -- $introduction

    -- ** Hashing a message
    HashKey
  , newHashKey
  , Hash
  , hashByteString

    -- ** Hashing a multi-part message
  , Multipart
  , withMultipart
  , updateMultipart

    -- ** Conversion
  , hashToHexText
  , hashToHexByteString
  , hashToBinary
  )
where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import qualified Data.Text.Builder.Linear as Builder
import Data.Text.Display
import Foreign (Ptr)
import qualified Foreign
import Foreign.C (CChar, CInt, CSize, CUChar, CULLong)
import Foreign.ForeignPtr
import Foreign.Storable

import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.Base16.Types as Base16
import Data.Kind (Type)
import LibSodium.Bindings.GenericHashing
  ( CryptoGenericHashState
  , cryptoGenericHash
  , cryptoGenericHashBytes
  , cryptoGenericHashFinal
  , cryptoGenericHashInit
  , cryptoGenericHashKeyBytes
  , cryptoGenericHashKeyGen
  , cryptoGenericHashStateBytes
  , cryptoGenericHashUpdate
  )
import Sel.Internal
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
--
-- This API computes a fixed-length fingerprint for an arbitrarily long message.
-- It is backed by the [BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_\(hash_function\)) algorithm.
--
-- Sample use cases:
--
--   * File integrity checking
--   * Creating unique identifiers to index arbitrarily long data
--
-- __⚠️ Do not use this module to hash passwords! ⚠️__ Please use the "Sel.Hashing.Password" module instead.
--
-- If you need to deviate from the defaults enforced by this module,
-- please use the underlying bindings at "LibSodium.Bindings.GenericHashing".

-- | The 'HashKey' is used to produce distinct fingerprints for the same message.
-- It is optional to use, and 'hashByteString' will always produce the same fingerprint
-- for the same message if a 'HashKey' is not given. This behaviour is similar to
-- MD5 and SHA-1 functions, for which 'hashByteString' is a faster and more secure alternative.
--
-- Create a new 'HashKey' with 'newHashKey'.
--
-- @since 0.0.1.0
newtype HashKey = HashKey (ForeignPtr CUChar)

instance Eq HashKey where
  (HashKey hk1) == (HashKey hk2) =
    foreignPtrEq hk1 hk2 cryptoGenericHashKeyBytes

instance Ord HashKey where
  compare (HashKey hk1) (HashKey hk2) =
    foreignPtrOrd hk1 hk2 cryptoGenericHashKeyBytes

-- | Create a new 'HashKey' of size 'cryptoGenericHashKeyBytes'.
--
-- @since 0.0.1.0
newHashKey :: IO HashKey
newHashKey = do
  fPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashKeyBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    cryptoGenericHashKeyGen ptr
  pure $ HashKey fPtr

-- | The fingerprint computed by @hashByteString@.
-- It is produced by the BLAKE2b algorithm, and is
-- of size 'cryptoGenericHashBytes', as recommended.
--
-- You can produce a human-readable string representation
-- of a 'Hash' by using the @display@ function.
--
-- @since 0.0.1.0
newtype Hash = Hash (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Hash where
  (Hash h1) == (Hash h2) =
    foreignPtrEq h1 h2 cryptoGenericHashBytes

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash h1) (Hash h2) =
    foreignPtrOrd h1 h2 cryptoGenericHashBytes

-- |
--
-- @since 0.0.1.0
instance Storable Hash where
  sizeOf :: Hash -> Int
  sizeOf _ = fromIntegral cryptoGenericHashBytes

  --  Aligned on the size of 'cryptoGenericHashBytes'
  alignment :: Hash -> Int
  alignment _ = 32

  poke :: Ptr Hash -> Hash -> IO ()
  poke ptr (Hash hashForeignPtr) =
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.copyArray (Foreign.castPtr ptr) hashPtr (fromIntegral cryptoGenericHashKeyBytes)

  peek :: Ptr Hash -> IO Hash
  peek ptr = do
    hashfPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashKeyBytes)
    Foreign.withForeignPtr hashfPtr $ \hashPtr ->
      Foreign.copyArray hashPtr (Foreign.castPtr ptr) (fromIntegral cryptoGenericHashKeyBytes)
    pure $ Hash hashfPtr

-- |
--
-- @since 0.0.1.0
instance Display Hash where
  displayBuilder = Builder.fromText . hashToHexText

-- |
--
-- @since 0.0.1.0
instance Show Hash where
  show = BS.unpackChars . hashToHexByteString

-- | Hash a 'StrictByteString' with the BLAKE2b algorithm, and an optional key.
--
-- Without a 'HashKey', hashing the same data twice will give the same result.
--
-- @since 0.0.1.0
hashByteString :: Maybe HashKey -> StrictByteString -> IO Hash
hashByteString mHashKey bytestring =
  case mHashKey of
    Just (HashKey fPtr) ->
      Foreign.withForeignPtr fPtr $ \keyPtr ->
        doHashByteString keyPtr cryptoGenericHashKeyBytes
    Nothing ->
      doHashByteString Foreign.nullPtr 0
  where
    doHashByteString :: Ptr a -> CSize -> IO Hash
    doHashByteString keyPtr keyLength =
      unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
        hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashBytes)
        Foreign.withForeignPtr hashForeignPtr $ \hashPtr -> do
          void $
            cryptoGenericHash
              hashPtr
              cryptoGenericHashBytes
              (Foreign.castPtr cString :: Ptr CUChar)
              (fromIntegral cStringLen)
              (Foreign.castPtr keyPtr :: Ptr CUChar)
              keyLength
        pure $ Hash hashForeignPtr

-- | Convert a 'Hash' to a strict, hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
hashToHexText :: Hash -> Text
hashToHexText = Base16.extractBase16 . Base16.encodeBase16 . hashToBinary

-- | Convert a 'Hash' to a strict, hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
hashToHexByteString :: Hash -> StrictByteString
hashToHexByteString (Hash hashPtr) = binaryToHex hashPtr cryptoGenericHashBytes

-- | Convert a 'Hash' to a strict binary 'StrictByteString'.
--
-- @since 0.0.1.0
hashToBinary :: Hash -> StrictByteString
hashToBinary (Hash fPtr) =
  BS.fromForeignPtr (Foreign.castForeignPtr fPtr) 0 hashBytesSize
  where
    hashBytesSize = fromIntegral cryptoGenericHashBytes

-- ** Hashing a multi-part message

-- | 'Multipart' is a cryptographic context for streaming hashing.
-- This API can be used when a message is too big to fit
-- in memory or when the message is received in portions.
--
-- Use it like this:
--
-- >>> hashKey <- Hashing.newHashKey
-- >>> hash <- Hashing.withMultipart (Just hashKey) $ \multipartState -> do -- we are in MonadIO
-- ...   message1 <- getMessage
-- ...   Hashing.updateMultipart multipartState message1
-- ...   message2 <- getMessage
-- ...   Hashing.updateMultipart multipartState message2
--
-- @since 0.0.1.0
newtype Multipart s = Multipart (Ptr CryptoGenericHashState)

type role Multipart nominal

-- | Perform streaming hashing with a 'Multipart' cryptographic context.
-- If there is no 'HashKey', you will get the same output for the same input all the time.
--
-- Use 'Hashing.updateMultipart' within the continuation to add more message parts to be hashed.
--
-- The context is safely allocated first, then the continuation is run
-- and then it is deallocated after that.
--
-- @since 0.0.1.0
withMultipart
  :: forall (a :: Type) (m :: Type -> Type)
   . MonadIO m
  => Maybe HashKey
  -- ^ Optional cryptographic key
  -> (forall s. Multipart s -> m a)
  -- ^ Continuation that gives you access to a 'Multipart' cryptographic context
  -> m Hash
withMultipart mKey actions = do
  allocateWith cryptoGenericHashStateBytes $ \statePtr -> do
    case mKey of
      Just (HashKey hashKeyFPtr) ->
        liftIO $ Foreign.withForeignPtr hashKeyFPtr $ \(hashKeyPtr :: Ptr CUChar) ->
          liftIO $
            initMultipart
              statePtr
              hashKeyPtr
              cryptoGenericHashKeyBytes
      Nothing ->
        liftIO $
          initMultipart
            statePtr
            Foreign.nullPtr
            0
    let part = Multipart statePtr
    actions part
    finaliseMultipart part

-- Internal
initMultipart
  :: Ptr CryptoGenericHashState
  -> Ptr CUChar
  -> CSize
  -> IO CInt
initMultipart statePtr hashKeyPtr hashKeyLength =
  cryptoGenericHashInit
    statePtr
    hashKeyPtr
    hashKeyLength
    cryptoGenericHashBytes

-- | Compute the 'Hash' of all the portions that were fed to the cryptographic context.
--
--  this function is only used within 'withMultipart'
--
--  @since 0.0.1.0
finaliseMultipart :: MonadIO m => Multipart s -> m Hash
finaliseMultipart (Multipart statePtr) = liftIO $ do
  hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoGenericHashBytes)
  Foreign.withForeignPtr hashForeignPtr $ \(hashPtr :: Ptr CUChar) ->
    void $
      cryptoGenericHashFinal
        statePtr
        hashPtr
        cryptoGenericHashBytes
  pure $ Hash hashForeignPtr

-- | Add a message portion to be hashed.
--
-- This function is to be used within 'withMultipart'.
--
-- @since 0.0.1.0
updateMultipart :: forall (m :: Type -> Type) (s :: Type). MonadIO m => Multipart s -> StrictByteString -> m ()
updateMultipart (Multipart statePtr) message = liftIO $ do
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    let messagePtr = Foreign.castPtr @CChar @CUChar cString
    let messageLen = fromIntegral @Int @CULLong cStringLen
    void $
      cryptoGenericHashUpdate
        statePtr
        messagePtr
        messageLen
