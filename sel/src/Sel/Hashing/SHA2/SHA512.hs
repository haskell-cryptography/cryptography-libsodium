{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Sel.Hashing.SHA2.SHA512
-- Description: SHA-512 hashing
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.SHA2.SHA512
  ( -- ** Usage
    -- $usage

    -- ** Hash
    Hash
  , hashToBinary
  , hashToHexText
  , hashToHexByteString

    -- ** Hashing a single message
  , hashByteString
  , hashText

    -- ** Hashing a multi-parts message
  , Multipart
  , withMultipart
  , updateMultipart
  , finaliseMultipart
  ) where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import Data.Text.Display (Display (..))
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Internal.Builder as Builder
import Foreign (ForeignPtr, Ptr, Storable)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import LibSodium.Bindings.SHA2 (CryptoHashSHA512State, cryptoHashSHA512, cryptoHashSHA512Bytes, cryptoHashSHA512Final, cryptoHashSHA512Init, cryptoHashSHA512StateBytes, cryptoHashSHA512Update)
import System.IO.Unsafe (unsafeDupablePerformIO)

import Sel.Internal

-- $usage
--
-- The SHA-2 family of hashing functions is only provided for interoperability with other applications.
--
-- If you are looking for a generic hash function, do use 'Sel.Hashing.Generic'.
--
-- If you are looking to hash passwords or deriving keys from passwords, do use 'Sel.Hashing.Password',
-- as the functions of the SHA-2 family are not suitable for this task.
--
-- Only import this module qualified like this:
--
-- >>> import qualified Sel.Hashing.SHA2.SHA512 as SHA512

-- | A hashed value from the SHA-512 algorithm.
--
-- @since 0.0.1.0
newtype Hash = Hash (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq Hash where
  (Hash h1) == (Hash h2) =
    unsafeDupablePerformIO $
      foreignPtrEq h1 h2 cryptoHashSHA512Bytes

-- |
--
-- @since 0.0.1.0
instance Ord Hash where
  compare (Hash h1) (Hash h2) =
    unsafeDupablePerformIO $
      foreignPtrOrd h1 h2 cryptoHashSHA512Bytes

-- |
--
-- @since 0.0.1.0
instance Storable Hash where
  sizeOf :: Hash -> Int
  sizeOf _ = fromIntegral cryptoHashSHA512Bytes

  --  Aligned on the size of 'cryptoHashSHA512Bytes'
  alignment :: Hash -> Int
  alignment _ = 32

  poke :: Ptr Hash -> Hash -> IO ()
  poke ptr (Hash hashForeignPtr) =
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      Foreign.copyArray (Foreign.castPtr ptr) hashPtr (fromIntegral cryptoHashSHA512Bytes)

  peek :: Ptr Hash -> IO Hash
  peek ptr = do
    hashfPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA512Bytes)
    Foreign.withForeignPtr hashfPtr $ \hashPtr ->
      Foreign.copyArray hashPtr (Foreign.castPtr ptr) (fromIntegral cryptoHashSHA512Bytes)
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

-- ** Hashing a single message

-- | Convert a 'Hash' to a strict hexadecimal 'Text'.
--
-- @since 0.0.1.0
hashToHexText :: Hash -> Text
hashToHexText = Text.decodeUtf8 . hashToBinary

-- | Convert a 'Hash' to a strict, hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
hashToHexByteString :: Hash -> StrictByteString
hashToHexByteString = Base16.encodeBase16' . hashToBinary

-- | Convert a 'Hash' to a binary 'StrictByteString'.
--
-- @since 0.0.1.0
hashToBinary :: Hash -> StrictByteString
hashToBinary (Hash fPtr) =
  BS.fromForeignPtr
    (Foreign.castForeignPtr fPtr)
    0
    (fromIntegral @CSize @Int cryptoHashSHA512Bytes)

-- | Hash a 'StrictByteString' with the SHA-512 algorithm.
--
-- @since 0.0.1.0
hashByteString :: StrictByteString -> IO Hash
hashByteString bytestring =
  BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA512Bytes)
    Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
      void $
        cryptoHashSHA512
          hashPtr
          (Foreign.castPtr cString :: Ptr CUChar)
          (fromIntegral @Int @CULLong cStringLen)
    pure $ Hash hashForeignPtr

-- | Hash a UTF8-encoded strict 'Text' with the SHA-512 algorithm.
--
-- @since 0.0.1.0
hashText :: Text -> IO Hash
hashText text = hashByteString (Text.encodeUtf8 text)

-- ** Hashing a multi-parts message

-- | 'Multipart' is a cryptographic context for streaming hashing.
-- This API can be used when a message is too big to fit in memory or when the message is received in portions.
--
-- Use it like this:
--
-- >>> hash <- SHA512.withMultipart $ \multipartState -> do -- we are in the IO monad
-- ...   message1 <- getMessage
-- ...   SHA512.updateMultipart multipartState message1
-- ...   message2 <- getMessage
-- ...   SHA512.updateMultipart multipartState message2
-- ...   SHA512.finaliseMultipart multipart
--
-- @since 0.0.1.0
newtype Multipart = Multipart (Ptr CryptoHashSHA512State)

-- | Perform streaming hashing with a 'Multipart' cryptographic context.
--
-- Use 'SHA512.updateMultipart' and 'SHA512.finaliseMultipart' inside of the continuation.
--
-- The context is safely allocated and deallocated inside of the continuation.
--
-- Do not try to jailbreak the context outside of the action, this will not be pleasant.
--
-- @since 0.0.1.0
withMultipart
  :: forall a
   . (Multipart -> IO a)
  -- ^ Continuation that gives you access to a 'Multipart' cryptographic context
  -> IO a
withMultipart action = do
  allocateWith cryptoHashSHA512StateBytes $ \statePtr -> do
    void $ cryptoHashSHA512Init statePtr
    action (Multipart statePtr)

-- | Add a message portion to be hashed.
--
-- This function should be used within 'withMultipart'.
--
-- @since 0.0.1.0
updateMultipart :: Multipart -> StrictByteString -> IO ()
updateMultipart (Multipart statePtr) message = do
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    let messagePtr = Foreign.castPtr @CChar @CUChar cString
    let messageLen = fromIntegral @Int @CULLong cStringLen
    void $
      cryptoHashSHA512Update
        statePtr
        messagePtr
        messageLen

-- | Compute the 'Hash' of all the portions that were fed to the cryptographic context.
--
-- This function should be used within 'withMultipart'.
--
-- @since 0.0.1.0
finaliseMultipart :: Multipart -> IO Hash
finaliseMultipart (Multipart statePtr) = do
  hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoHashSHA512Bytes)
  Foreign.withForeignPtr hashForeignPtr $ \(hashPtr :: Ptr CUChar) ->
    void $
      cryptoHashSHA512Final
        statePtr
        hashPtr
  pure $ Hash hashForeignPtr
