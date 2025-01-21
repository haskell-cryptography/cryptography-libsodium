{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.Hashing.Password
-- Description: Password hashing with the Argon2id algorithm
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.Hashing.Password
  ( -- * Introduction
    -- $introduction
    PasswordHash

    -- ** Password Hashing and Verifying
  , hashByteString
  , hashText
  , verifyByteString
  , verifyText
  , hashByteStringWithParams

    -- *** Conversion
  , passwordHashToByteString
  , passwordHashToText
  , passwordHashToHexText
  , passwordHashToHexByteString
  , asciiTextToPasswordHash
  , asciiByteStringToPasswordHash

    -- ** Salt
  , Salt
  , genSalt

    -- ** Conversion
  , saltToBinary
  , saltToHexText
  , saltToHexByteString
  , binaryToSalt
  , hexTextToSalt
  , hexByteStringToSalt

    -- * Argon2 Parameters
  , Argon2Params (Argon2Params)
  , defaultArgon2Params
  )
where

import Control.Monad (void)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as Char8
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import qualified Data.Text.Builder.Linear as Builder
import Data.Text.Display
import qualified Data.Text.Encoding as Text
import Foreign hiding (void)
import Foreign.C
import System.IO.Unsafe (unsafeDupablePerformIO)

import Sel.Internal

import qualified Data.Base16.Types as Base16
import GHC.Generics
import LibSodium.Bindings.PasswordHashing
import LibSodium.Bindings.Random
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
--
-- This API provides functions for password hashing, backed by the [Argon2id](https://en.wikipedia.org/wiki/Argon2) algorithm.
--
-- If you need to deviate from the defaults enforced by this module,
-- please use the underlying bindings at "LibSodium.Bindings.PasswordHashing".

-- | A hashed password from the Argon2id algorithm.
--
-- @since 0.0.1.0
newtype PasswordHash = PasswordHash (ForeignPtr CChar)
  deriving stock (Generic)

-- | @since 0.0.1.0
instance Display PasswordHash where
  displayBuilder = Builder.fromText . passwordHashToHexText

-- | @since 0.0.1.0
instance Eq PasswordHash where
  (PasswordHash ph1) == (PasswordHash ph2) =
    foreignPtrEq
      (Foreign.castForeignPtr @CChar @CUChar ph1)
      (Foreign.castForeignPtr @CChar @CUChar ph2)
      cryptoPWHashStrBytes

-- | @since 0.0.1.0
instance Ord PasswordHash where
  (PasswordHash ph1) `compare` (PasswordHash ph2) =
    foreignPtrOrd
      (Foreign.castForeignPtr @CChar @CUChar ph1)
      (Foreign.castForeignPtr @CChar @CUChar ph2)
      cryptoPWHashStrBytes

-- | @since 0.0.1.0
instance Show PasswordHash where
  show s = showHash s
    where
      showHash :: PasswordHash -> String
      showHash = show . passwordHashToText

-- | Hash the password with the Argon2id algorithm and a set of pre-defined parameters.
--
-- The hash is encoded in a human-readable format that includes:
--
--   * The result of a memory-hard, CPU-intensive hash function applied to the password;
--   * The automatically generated salt used for the previous computation;
--   * The other parameters required to verify the password, including the algorithm
--     identifier, its version, opslimit, and memlimit.
--
-- Example output: @$argon2id$v=19$m=262144,t=3,p=1$fpPdXj9mK7J4m…@
--
-- @since 0.0.1.0
hashByteString :: StrictByteString -> IO PasswordHash
hashByteString bytestring =
  BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoPWHashStrBytes)
    Foreign.withForeignPtr hashForeignPtr $ \passwordHashPtr ->
      void $
        cryptoPWHashStr
          passwordHashPtr
          cString
          (fromIntegral @Int @CULLong cStringLen)
          cryptoPWHashOpsLimitModerate
          cryptoPWHashMemLimitModerate
    pure $ PasswordHash hashForeignPtr

-- | Hash a UTF8-encoded password with the Argon2id algorithm and
-- a set of pre-defined parameters.
--
-- @since 0.0.1.0
hashText :: Text -> IO PasswordHash
hashText text = hashByteString (Text.encodeUtf8 text)

-- | Hash the password with the Argon2id algorithm.
--
-- The hash is __not__ encoded in human-readable format.
--
-- @since 0.0.1.0
hashByteStringWithParams :: Argon2Params -> Salt -> StrictByteString -> IO PasswordHash
hashByteStringWithParams Argon2Params{opsLimit, memLimit} (Salt argonSalt) bytestring =
  BS.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    BS.unsafeUseAsCStringLen argonSalt $ \(saltString, _) -> do
      hashForeignPtr <- mallocForeignPtrBytes (fromIntegral cryptoPWHashStrBytes)
      withForeignPtr hashForeignPtr $ \passwordHashPtr ->
        void $
          cryptoPWHash
            passwordHashPtr
            (fromIntegral @CSize @CLLong cryptoPWHashStrBytes)
            cString
            (fromIntegral @Int @CULLong cStringLen)
            (castPtr saltString)
            opsLimit
            memLimit
            cryptoPWHashAlgDefault
      pure $ PasswordHash (castForeignPtr @CUChar @CChar hashForeignPtr)

-- | Verify the password hash against a clear 'Text' password
--
-- This function purposefully takes some time to complete, in order to alleviate bruteforce attacks.
--
-- @since 0.0.1.0
verifyText :: PasswordHash -> Text -> Bool
verifyText passwordHash clearTextPassword = verifyByteString passwordHash (Text.encodeUtf8 clearTextPassword)

-- | Verify the password hash against a clear 'StrictByteString' password
--
-- This function purposefully takes some time to complete, in order to alleviate bruteforce attacks.
--
-- @since 0.0.1.0
verifyByteString :: PasswordHash -> StrictByteString -> Bool
verifyByteString (PasswordHash fPtr) clearTextPassword = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen clearTextPassword $ \(cString, cStringLen) -> do
    Foreign.withForeignPtr fPtr $ \hashPtr -> do
      result <-
        cryptoPWHashStrVerify
          hashPtr
          cString
          (fromIntegral @Int @CULLong cStringLen)
      pure $ result == 0

-- | Convert a 'PasswordHash' to a 'StrictByteString'.
--
-- @since 0.0.1.0
passwordHashToByteString :: PasswordHash -> StrictByteString
passwordHashToByteString (PasswordHash fPtr) = unsafeDupablePerformIO $
  Foreign.withForeignPtr fPtr $ \hashPtr -> do
    resultByteString <- BS.unsafePackCStringLen (hashPtr, fromIntegral @CSize @Int cryptoPWHashStrBytes)
    pure $ Char8.dropWhileEnd (== '\NUL') resultByteString

-- | Convert a 'PasswordHash' to a strict 'Text'.
--
-- @since 0.0.1.0
passwordHashToText :: PasswordHash -> Text
passwordHashToText passwordHash =
  let bs = passwordHashToByteString passwordHash
      (prefix, suffix) = Text.decodeASCIIPrefix bs
   in case BS.uncons suffix of
        Nothing -> prefix
        Just (word, _) ->
          let !errPos = BS.length bs - BS.length suffix
           in error $ "decodeASCII: detected non-ASCII codepoint " ++ show word ++ " at position " ++ show errPos <> ". " <> show bs

-- | Convert a 'PasswordHash' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- It is recommended to use this one on a 'PasswordHash' produced by 'hashByteStringWithParams'.
--
-- @since 0.0.1.0
passwordHashToHexByteString :: PasswordHash -> StrictByteString
passwordHashToHexByteString (PasswordHash passwordHashForeignPtr) =
  binaryToHex (Foreign.castForeignPtr @CChar @CUChar passwordHashForeignPtr) cryptoPWHashStrBytes

-- | Convert a 'PasswordHash' to a strict hexadecimal-encoded 'Text'.
--
-- It is recommended to use this one on a 'PasswordHash' produced by 'hashByteStringWithParams'.
--
-- @since 0.0.1.0
passwordHashToHexText :: PasswordHash -> Text
passwordHashToHexText = Base16.extractBase16 . Base16.encodeBase16 . passwordHashToByteString

-- | Convert an ascii-encoded password hash to a 'PasswordHash'
--
-- This function does not perform ASCII validation.
--
-- @since 0.0.1.0
asciiTextToPasswordHash :: Text -> PasswordHash
asciiTextToPasswordHash = asciiByteStringToPasswordHash . Text.encodeUtf8

-- | Convert an ascii-encoded password hash to a 'PasswordHash'
--
-- This function does not perform ASCII validation.
--
-- @since 0.0.1.0
asciiByteStringToPasswordHash :: StrictByteString -> PasswordHash
asciiByteStringToPasswordHash textualHash = unsafeDupablePerformIO $ do
  destinationFPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoPWHashStrBytes)
  Foreign.withForeignPtr destinationFPtr $ \destinationPtr -> do
    BS.useAsCStringLen textualHash $ \(sourcePtr, len) -> do
      Foreign.fillBytes destinationPtr 0 (fromIntegral cryptoPWHashStrBytes)
      Foreign.copyBytes destinationPtr sourcePtr len
      pure $ PasswordHash destinationFPtr

-- | The 'Salt' is used in conjunction with 'hashByteStringWithParams'
-- when you want to manually provide the piece of data that will
-- differentiate two fingerprints of the same password.
--
-- It is automatically taken care of for you when you use
-- 'hashByteString' or 'hashText'.
--
-- Use 'genSalt' to create a 'Salt' of size
-- equal to the constant 'cryptoPWHashSaltBytes'.
--
-- @since 0.0.1.0
newtype Salt = Salt StrictByteString
  deriving newtype
    ( Eq
      -- ^ @since 0.0.1.0
    , Ord
      -- ^ @since 0.0.1.0
    , Show
      -- ^ @since 0.0.1.0
    )

-- |
--
-- @since 0.0.1.0
instance Display Salt where
  displayBuilder salt = Builder.fromText . saltToHexText $ salt

-- | Generate a random 'Salt' for password hashing
--
-- @since 0.0.1.0
genSalt :: IO Salt
genSalt =
  Salt
    <$> BS.create
      (fromIntegral cryptoPWHashSaltBytes)
      (`randombytesBuf` cryptoPWHashSaltBytes)

-- | Convert 'Salt' to underlying 'StrictByteString' binary.
--
-- @since 0.0.2.0
saltToBinary :: Salt -> StrictByteString
saltToBinary (Salt bs) = bs

-- | Convert 'Salt' to a strict hexadecimal-encoded 'Text'.
--
-- @since 0.0.2.0
saltToHexText :: Salt -> Text
saltToHexText = Base16.extractBase16 . Base16.encodeBase16 . saltToBinary

-- | Convert 'Salt' to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.2.0
saltToHexByteString :: Salt -> StrictByteString
saltToHexByteString = Base16.extractBase16 . Base16.encodeBase16' . saltToBinary

-- | Convert 'StrictByteString' to 'Salt'.
--
-- The input salt must be of length 'cryptoPWHashSaltBytes'.
--
-- @since 0.0.2.0
binaryToSalt :: StrictByteString -> Maybe Salt
binaryToSalt bs =
  if BS.length bs /= fromIntegral cryptoPWHashSaltBytes
    then Nothing
    else Just (Salt bs)

-- | Convert a strict hexadecimal-encoded 'Text' to a 'Salt'.
--
-- The input salt, once decoded from base16, must be of length 'cryptoPWHashSaltBytes'.
--
-- @since 0.0.1.0
hexTextToSalt :: Text -> Maybe Salt
hexTextToSalt = hexByteStringToSalt . Text.encodeUtf8

-- | Convert a hexadecimal-encoded 'StrictByteString' to a 'Salt'.
--
-- The input salt, once decoded from base16, must be of length 'cryptoPWHashSaltBytes'.
--
-- @since 0.0.1.0
hexByteStringToSalt :: StrictByteString -> Maybe Salt
hexByteStringToSalt hexByteString =
  case Base16.decodeBase16Untyped hexByteString of
    Right binary -> binaryToSalt binary
    Left _ -> Nothing

-- |
--
-- @since 0.0.1.0
data Argon2Params = Argon2Params
  { opsLimit :: CULLong
  , memLimit :: CSize
  }

-- | These are the default parameters with which 'hashByteStringWithParams' can be invoked:
--
-- * /opsLimit/ = 'cryptoPWHashOpsLimitModerate'
-- * /memLimit/ = 'cryptoPWHashMemLimitModerate'
--
-- @since 0.0.1.0
defaultArgon2Params :: Argon2Params
defaultArgon2Params =
  Argon2Params
    { opsLimit = cryptoPWHashOpsLimitModerate
    , memLimit = cryptoPWHashMemLimitModerate
    }
