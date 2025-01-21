{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.Hashing.Short
-- Description: Short input hashing with the SipHash-2-4 algorithm
-- Copyright: (C) Hécate Moonlight 2023
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.Short
  ( -- ** Introduction
    -- $introduction
    ShortHash

    -- ** Short-input Hashing
  , hashByteString
  , hashText

    -- *** Conversion
  , shortHashToBinary
  , shortHashToHexText
  , shortHashToHexByteString

    -- ** Short Hash Key
  , ShortHashKey
  , newKey

    -- *** Conversion
  , shortHashKeyToBinary
  , shortHashKeyToHexText
  , shortHashKeyToHexByteString
  , binaryToShortHashKey
  , hexTextToShortHashKey
  , hexByteStringToShortHashKey

    -- ** Errors
  , ShortHashingException (..)
  )
where

import Control.Exception (throw)
import Control.Monad (void, when)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Builder.Linear as Builder
import qualified Data.Text.Encoding as Text
import Foreign hiding (void)
import Foreign.C (CChar, CSize, CUChar, CULLong)
import GHC.Exception (Exception)
import System.IO.Unsafe (unsafeDupablePerformIO)

import qualified Data.Base16.Types as Base16
import Data.Text.Display
import LibSodium.Bindings.ShortHashing
  ( cryptoShortHashSipHashX24Bytes
  , cryptoShortHashSipHashX24KeyBytes
  , cryptoShortHashX24
  , cryptoShortHashX24KeyGen
  )
import Sel.Internal
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
--
-- This module provides an API for performant short-input hashing,
-- backed by the [SipHash-2-4](https://en.wikipedia.org/wiki/SipHash) algorithm.
--
-- Short-input hashing functions have a variety of use-cases, such as:
--
-- * Hash Tables
-- * Probabilistic data structures, such as Bloom filters
-- * Integrity checking in interactive protocols

-- | A 128-bit hash of a short input, of size 'cryptoShortHashSipHashX24Bytes'
--
-- @since 0.0.1.0
newtype ShortHash = ShortHash (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq ShortHash where
  (ShortHash sh1) == (ShortHash sh2) =
    foreignPtrEq sh1 sh2 cryptoShortHashSipHashX24Bytes

-- |
--
-- @since 0.0.1.0
instance Ord ShortHash where
  compare (ShortHash sh1) (ShortHash sh2) =
    foreignPtrOrd sh1 sh2 cryptoShortHashSipHashX24Bytes

-- |
--
-- @since 0.0.1.0
instance Show ShortHash where
  show = Text.unpack . shortHashToHexText

-- |
--
-- @since 0.0.1.0
instance Display ShortHash where
  displayBuilder = Builder.fromText . shortHashToHexText

-- | Hash a 'StrictByteString'.
--
-- The same message hashed with the same key will always produce the same output.
--
-- The 'ShortHash' is of length 'cryptoShortHashSipHashX24Bytes'
--
-- @since 0.0.1.0
hashByteString
  :: ShortHashKey
  -- ^ Random key produced by 'newKey'
  -> StrictByteString
  -- ^ Data to hash
  -> IO ShortHash
hashByteString (ShortHashKey keyFPtr) message =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    shortHashFPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoShortHashSipHashX24Bytes)
    Foreign.withForeignPtr keyFPtr $ \keyPtr ->
      Foreign.withForeignPtr shortHashFPtr $ \shortHashPtr -> do
        result <-
          cryptoShortHashX24
            shortHashPtr
            (Foreign.castPtr cString)
            (fromIntegral @Int @CULLong cStringLen)
            keyPtr
        when (result /= 0) $ throw ShortHashingException
        pure $ ShortHash shortHashFPtr

-- | Hash a strict 'Text'.
--
-- The same message hashed with the same key will always produce the same output.
--
-- The 'ShortHash' is of length 'cryptoShortHashSipHashX24Bytes'
--
-- @since 0.0.1.0
hashText
  :: ShortHashKey
  -- ^ Random key produced by 'newKey'
  -> Text
  -- ^ UTF-8 encoded data to hash
  -> IO ShortHash
hashText key message = hashByteString key (Text.encodeUtf8 message)

-- | Convert a 'ShortHash' to a strict binary 'StrictByteString'.
--
-- @since 0.0.1.0
shortHashToBinary :: ShortHash -> StrictByteString
shortHashToBinary (ShortHash hashFPtr) =
  BS.fromForeignPtr
    (Foreign.castForeignPtr hashFPtr)
    0
    (fromIntegral @CSize @Int cryptoShortHashSipHashX24Bytes)

-- | Convert a 'ShortHash' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
shortHashToHexByteString :: ShortHash -> StrictByteString
shortHashToHexByteString (ShortHash hashForeignPtr) =
  binaryToHex hashForeignPtr cryptoShortHashSipHashX24Bytes

-- | Convert a 'ShortHash' to a strict hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
shortHashToHexText :: ShortHash -> Text
shortHashToHexText = Base16.extractBase16 . Base16.encodeBase16 . shortHashToBinary

-- | A random key used for hashing, of size 'cryptoShortHashSipHashX24KeyBytes'.
--
-- The same message hashed with the same key will always produce the same output.
--
-- @since 0.0.1.0
newtype ShortHashKey = ShortHashKey (ForeignPtr CUChar)

-- |
--
-- @since 0.0.1.0
instance Eq ShortHashKey where
  (ShortHashKey sh1) == (ShortHashKey sh2) =
    foreignPtrEq sh1 sh2 cryptoShortHashSipHashX24Bytes

-- |
--
-- @since 0.0.1.0
instance Ord ShortHashKey where
  compare (ShortHashKey sh1) (ShortHashKey sh2) =
    foreignPtrOrd sh1 sh2 cryptoShortHashSipHashX24Bytes

-- |
--
-- @since 0.0.1.0
instance Show ShortHashKey where
  show = Text.unpack . shortHashKeyToHexText

instance Display ShortHashKey where
  displayBuilder = Builder.fromText . shortHashKeyToHexText

-- | Generate a random 'ShortHashKey' of size 'cryptoShortHashSipHashX24KeyBytes'
--
-- @since 0.0.1.0
newKey :: IO ShortHashKey
newKey = do
  shortHashKeyForeignPtr <-
    Foreign.mallocForeignPtrBytes (fromIntegral cryptoShortHashSipHashX24KeyBytes)
  Foreign.withForeignPtr shortHashKeyForeignPtr $ \shortHashKeyPtr ->
    void $ cryptoShortHashX24KeyGen shortHashKeyPtr
  pure $ ShortHashKey shortHashKeyForeignPtr

-- | Convert a 'ShortHash' to a strict binary 'StrictByteString'.
--
-- @since 0.0.1.0
shortHashKeyToBinary :: ShortHashKey -> StrictByteString
shortHashKeyToBinary (ShortHashKey hashKeyFPtr) =
  BS.fromForeignPtr
    (Foreign.castForeignPtr hashKeyFPtr)
    0
    (fromIntegral @CSize @Int cryptoShortHashSipHashX24KeyBytes)

-- | Convert a 'ShortHashKey' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
shortHashKeyToHexByteString :: ShortHashKey -> StrictByteString
shortHashKeyToHexByteString (ShortHashKey hashKeyForeignPtr) =
  binaryToHex hashKeyForeignPtr cryptoShortHashSipHashX24KeyBytes

-- | Convert a 'ShortHash' to a strict hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
shortHashKeyToHexText :: ShortHashKey -> Text
shortHashKeyToHexText = Base16.extractBase16 . Base16.encodeBase16 . shortHashKeyToBinary

-- | Convert a binary 'StrictByteString' to a 'ShortHashKey'.
--
-- The input key must be of length 'cryptoShortHashSipHashX24KeyBytes'
--
-- @since 0.0.1.0
binaryToShortHashKey :: StrictByteString -> Maybe ShortHashKey
binaryToShortHashKey binaryKey =
  if BS.length binaryKey /= fromIntegral cryptoShortHashSipHashX24KeyBytes
    then Nothing
    else unsafeDupablePerformIO $ do
      BS.unsafeUseAsCString binaryKey $ \cString -> do
        shortHashKeyFPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoShortHashSipHashX24KeyBytes)
        Foreign.withForeignPtr shortHashKeyFPtr $ \shortHashKeyPtr ->
          Foreign.copyBytes
            shortHashKeyPtr
            (Foreign.castPtr @CChar @CUChar cString)
            (fromIntegral cryptoShortHashSipHashX24KeyBytes)
        pure $ Just $ ShortHashKey shortHashKeyFPtr

-- | Convert a strict hexadecimal-encoded 'Text' to a 'ShortHashKey'.
--
-- The input key, once decoded from base16, must be of length 'cryptoShortHashSipHashX24KeyBytes'
--
-- @since 0.0.1.0
hexTextToShortHashKey :: Text -> Maybe ShortHashKey
hexTextToShortHashKey = hexByteStringToShortHashKey . Text.encodeUtf8

-- | Convert a hexadecimal-encoded 'StrictByteString' to a 'ShortHashKey'.
--
-- The input key, once decoded from base16, must be of length 'cryptoShortHashSipHashX24KeyBytes'
--
-- @since 0.0.1.0
hexByteStringToShortHashKey :: StrictByteString -> Maybe ShortHashKey
hexByteStringToShortHashKey hexByteString =
  case Base16.decodeBase16Untyped hexByteString of
    Right binary -> binaryToShortHashKey binary
    Left _ -> Nothing

-- | Exception thrown upon error during hashing by
-- 'hashByteString' or 'hashText'.
--
-- @since 0.0.1.0
data ShortHashingException = ShortHashingException
  deriving stock
    ( Show
      -- ^ @since 0.0.1.0
    , Eq
      -- ^ @since 0.0.1.0
    , Ord
      -- ^ @since 0.0.1.0
    )
  deriving anyclass
    ( Exception
      -- ^ @since 0.0.1.0
    )
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance ShortHashingException)
