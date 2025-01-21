{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.Scrypt
-- Description: Hashing with the Scrypt algorithm.
-- Copyright: (C) Seth Paul Hubbard 2023
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
module Sel.Scrypt
  ( -- ** Introduction
    -- $introduction
    ScryptHash

    -- ** Password Hashing and Verifying.
  , scryptHashPassword
  , scryptVerifyPassword

    -- *** Conversion
  , scryptHashToByteString
  , scryptHashToText
  , asciiTextToScryptHash
  , asciiByteStringToScryptHash
  )
where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString.Internal as BS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Text as Text
import qualified Data.Text.Builder.Linear as Builder
import Data.Text.Display
import qualified Data.Text.Encoding as Text
import Foreign hiding (void)
import Foreign.C
import LibSodium.Bindings.Scrypt
import Sel.Internal
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
--
-- This API is used for hashing and verifying passwords using the Scrypt algorithm.
-- This module is provided for interoperability with other applications. If you do
-- not need to use Scrypt specifically, use "Sel.Hashing.Password".

-- | A hashed password from the Scrypt algorithm.
--
-- @since 0.0.1.0
newtype ScryptHash = ScryptHash (ForeignPtr CChar)

-- | @since 0.0.1.0
instance Eq ScryptHash where
  (ScryptHash sh1) == (ScryptHash sh2) =
    foreignPtrEq
      (Foreign.castForeignPtr @CChar @CUChar sh1)
      (Foreign.castForeignPtr @CChar @CUChar sh2)
      cryptoPWHashScryptSalsa208SHA256StrBytes

-- | @since 0.0.1.0
instance Ord ScryptHash where
  compare (ScryptHash sh1) (ScryptHash sh2) =
    foreignPtrOrd
      (Foreign.castForeignPtr @CChar @CUChar sh1)
      (Foreign.castForeignPtr @CChar @CUChar sh2)
      cryptoPWHashScryptSalsa208SHA256StrBytes

-- | @since 0.0.1.0
instance Show ScryptHash where
  show = Text.unpack . scryptHashToText

-- | @since 0.0.1.0
instance Display ScryptHash where
  displayBuilder = Builder.fromText . scryptHashToText

-- | Hash the password with the Scrypt algorithm and a set of pre-defined parameters.
--
-- The hash is encoded in a human-readable format that includes:
--
--   * The result of a memory-hard, CPU-intensive hash function applied to the password;
--   * The automatically generated salt used for the previous computation;
--   * The other parameters required to verify the password, including the algorithm
--     identifier, its version, opslimit, and memlimit.
--
-- Example output: "$7$C6..../....dLONLMz8YfO/.EKvzwOeqWVVLmXg62MC.hL1m1sYtO/$X9eNjVxdD4jHAhOVid3OLzNkpv6ADJSAXygOxXqGHg7\NUL"
--
-- @since 0.0.1.0
scryptHashPassword :: StrictByteString -> IO ScryptHash
scryptHashPassword bytestring = do
  unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- mallocForeignPtrBytes (fromIntegral cryptoPWHashScryptSalsa208SHA256StrBytes)
    withForeignPtr hashForeignPtr $ \hashPtr ->
      void $
        cryptoPWHashScryptSalsa208SHA256Str
          hashPtr
          cString
          (fromIntegral cStringLen)
          (fromIntegral cryptoPWHashScryptSalsa208SHA256OpsLimitInteractive)
          cryptoPWHashScryptSalsa208SHA256MemLimitInteractive
    pure $ ScryptHash hashForeignPtr

-- | Verify a hashed password against a password verification string.
-- This returns True if successful.
--
-- @since 0.0.1.0
scryptVerifyPassword :: StrictByteString -> ScryptHash -> IO Bool
scryptVerifyPassword bytestring (ScryptHash sh) = do
  unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    withForeignPtr sh $ \scryptHash -> do
      result <-
        cryptoPWHashScryptSalsa208SHA256StrVerify
          scryptHash
          cString
          (fromIntegral cStringLen)
      return (result == 0)

-- | Convert a 'ScryptHash' to a binary 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
scryptHashToByteString :: ScryptHash -> StrictByteString
scryptHashToByteString (ScryptHash fPtr) =
  binaryToHex (Foreign.castForeignPtr @CChar @CUChar fPtr) cryptoPWHashScryptSalsa208SHA256StrBytes

-- | Convert a 'ScryptHash' to a hexadecimal-encoded 'Text'.
--
-- @since 0.0.1.0
scryptHashToText :: ScryptHash -> Text
scryptHashToText = Text.decodeASCII . scryptHashToByteString

-- | Convert an ASCII-encoded password hash to a 'ScryptHash'
--
-- This function does not perform ASCII validation.
--
-- @since 0.0.1.0
asciiByteStringToScryptHash :: StrictByteString -> ScryptHash
asciiByteStringToScryptHash textualHash =
  let (fPtr, _length) = BS.toForeignPtr0 textualHash
   in ScryptHash (castForeignPtr @Word8 @CChar fPtr)

-- | Convert an ASCII-encoded password hash to a 'ScryptHash'
--
-- This function does not perform ASCII validation.
--
-- @since 0.0.1.0
asciiTextToScryptHash :: Text -> ScryptHash
asciiTextToScryptHash = asciiByteStringToScryptHash . Text.encodeUtf8
