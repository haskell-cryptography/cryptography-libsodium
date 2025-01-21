{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.PublicKey.Cipher
-- Description: Authenticated encryption with public and secret keys
-- Copyright: (C) Hécate Moonlight 2022
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.PublicKey.Cipher
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Key pair generation
    newKeyPair
  , SecretKey (..)
  , unsafeSecretKeyToHexByteString
  , PublicKey (..)
  , publicKeyToHexByteString
  , keyPairFromHexByteStrings

    -- ** Nonce
  , Nonce (..)
  , nonceFromHexByteString
  , nonceToHexByteString

    -- ** Cipher text
  , CipherText (..)
  , cipherTextFromHexByteString
  , cipherTextToHexText
  , cipherTextToHexByteString
  , cipherTextToBinary

    -- ** Encryption and Decryption
  , encrypt
  , decrypt

    -- ** Errors
  , KeyPairGenerationException (..)
  , EncryptionError (..)
  ) where

import Control.Monad (when)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Builder.Linear as Builder
import Data.Text.Display (Display (displayBuilder), OpaqueInstance (..), ShowInstance (..))
import Data.Word (Word8)
import Foreign (ForeignPtr, Ptr)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import qualified Foreign.C as Foreign
import System.IO.Unsafe (unsafeDupablePerformIO)

import Control.Exception
import qualified Data.Base16.Types as Base16
import LibSodium.Bindings.CryptoBox
  ( cryptoBoxEasy
  , cryptoBoxKeyPair
  , cryptoBoxMACBytes
  , cryptoBoxNonceBytes
  , cryptoBoxOpenEasy
  , cryptoBoxPublicKeyBytes
  , cryptoBoxSecretKeyBytes
  )
import LibSodium.Bindings.Random (randombytesBuf)
import LibSodium.Bindings.SecureMemory (finalizerSodiumFree, sodiumFree, sodiumMalloc)
import Sel.Internal
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
-- Public-key authenticated encryption allows a sender to encrypt a confidential message
-- specifically for the recipient, using the recipient's public key.

-- $usage
--
-- > import qualified Sel.PublicKey.Cipher as Cipher
-- > import Sel (secureMain)
-- >
-- > main = secureMain $ do
-- >   -- We get the sender their pair of keys:
-- >   (senderSecretKey, senderPublicKey) <- newKeyPair
-- >   -- We get the nonce from the other party with the message, or with 'encrypt' and our own message.
-- >   (nonce, encryptedMessage) <- Cipher.encrypt "hello hello" secretKey
-- >   let result = Cipher.decrypt encryptedMessage secretKey nonce
-- >   print result
-- >   -- "Just \"hello hello\""

-- | A secret key of size 'cryptoBoxSecretKeyBytes'.
--
-- @since 0.0.1.0
newtype SecretKey = SecretKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
      -- > display secretKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" SecretKey)

-- |
--
-- @since 0.0.1.0
instance Eq SecretKey where
  (SecretKey hk1) == (SecretKey hk2) =
    foreignPtrEqConstantTime hk1 hk2 cryptoBoxSecretKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord SecretKey where
  compare (SecretKey hk1) (SecretKey hk2) =
    foreignPtrOrdConstantTime hk1 hk2 cryptoBoxSecretKeyBytes

-- | > show secretKey == "[REDACTED]"
--
-- @since 0.0.1.0
instance Show SecretKey where
  show _ = "[REDACTED]"

-- | A public key of size 'cryptoBoxPublicKeyBytes'.
--
-- @since 0.0.1.0
newtype PublicKey = PublicKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance PublicKey)

-- |
--
-- @since 0.0.1.0
instance Eq PublicKey where
  (PublicKey hk1) == (PublicKey hk2) =
    foreignPtrEq hk1 hk2 cryptoBoxPublicKeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord PublicKey where
  compare (PublicKey hk1) (PublicKey hk2) =
    foreignPtrOrd hk1 hk2 cryptoBoxPublicKeyBytes

-- |
--
-- @since 0.0.1.0
instance Show PublicKey where
  show = BS.unpackChars . publicKeyToHexByteString

-- | Convert a 'PublicKey' to a hexadecimal-encoded 'StrictByteString'.
--
-- @since 0.0.1.0
publicKeyToHexByteString :: PublicKey -> StrictByteString
publicKeyToHexByteString (PublicKey publicKeyForeignPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 publicKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoBoxPublicKeyBytes)

-- | Generate a new random secret key.
--
-- May throw 'KeyPairGenerationException' if the generation fails.
--
-- @since 0.0.1.0
newKeyPair :: IO (PublicKey, SecretKey)
newKeyPair = newKeyPairWith $ \publicKeyPtr secretKeyPtr -> do
  result <- cryptoBoxKeyPair publicKeyPtr secretKeyPtr
  when (result /= 0) $ throw KeyPairGenerationException

-- | Create a pair of 'SecretKey' and 'PublicKey'  from hexadecimal-encoded
-- 'StrictByteString's that you have obtained on your own, usually from the network or disk.
--
-- The public and secret keys, once decoded from base16, must respectively
-- be at least of length 'cryptoBoxPublicKeyBytes' and 'cryptoBoxSecretKeyBytes.
--
-- @since 0.0.1.0
keyPairFromHexByteStrings
  :: StrictByteString
  -- ^ Public key
  -> StrictByteString
  -- ^ Secret key
  -> Either Text (PublicKey, SecretKey)
keyPairFromHexByteStrings publicByteStringHex secretByteStringHex =
  case (Base16.decodeBase16Untyped publicByteStringHex, Base16.decodeBase16Untyped secretByteStringHex) of
    (Right publicByteString, Right secretByteString) ->
      if BS.length publicByteString < fromIntegral cryptoBoxPublicKeyBytes
        || BS.length secretByteString < fromIntegral cryptoBoxSecretKeyBytes
        then Left (Text.pack "Input too short")
        else unsafeDupablePerformIO $
          BS.unsafeUseAsCString publicByteString $ \outsidePublicKeyPtr ->
            BS.unsafeUseAsCString secretByteString $ \outsideSecretKeyPtr ->
              fmap Right $
                newKeyPairWith $ \publicKeyPtr secretKeyPtr -> do
                  Foreign.copyArray
                    (Foreign.castPtr @CUChar @CChar publicKeyPtr)
                    outsidePublicKeyPtr
                    (fromIntegral cryptoBoxPublicKeyBytes)

                  Foreign.copyArray
                    (Foreign.castPtr @CUChar @CChar secretKeyPtr)
                    outsideSecretKeyPtr
                    (fromIntegral cryptoBoxSecretKeyBytes)
    (_, Left msg) -> Left msg
    (Left msg, _) -> Left msg

-- | Prepare memory for a 'SecretKey' and 'PublicKey' pair,
-- and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc'
-- (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
newKeyPairWith
  :: ( Ptr CUChar
       -- \^ Public Key pointer
       -> Ptr CUChar
       -- \^ Secret Key pointer
       -> IO ()
     )
  -> IO (PublicKey, SecretKey)
newKeyPairWith action = do
  publicKeyPtr <- sodiumMalloc cryptoBoxPublicKeyBytes
  secretKeyPtr <- sodiumMalloc cryptoBoxSecretKeyBytes
  when (secretKeyPtr == Foreign.nullPtr || publicKeyPtr == Foreign.nullPtr) $ do
    sodiumFree secretKeyPtr
    sodiumFree publicKeyPtr
    Foreign.throwErrno "sodium_malloc failed to allocate memory"

  secretKeyForeignPtr <- Foreign.newForeignPtr_ secretKeyPtr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree secretKeyForeignPtr
  publicKeyForeignPtr <- Foreign.newForeignPtr_ publicKeyPtr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree publicKeyForeignPtr

  action publicKeyPtr secretKeyPtr
  pure (PublicKey publicKeyForeignPtr, SecretKey secretKeyForeignPtr)

-- | Convert a 'SecretKey' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeSecretKeyToHexByteString :: SecretKey -> StrictByteString
unsafeSecretKeyToHexByteString (SecretKey secretKeyForeignPtr) =
  binaryToHex secretKeyForeignPtr cryptoBoxSecretKeyBytes

-- | A random number that must only be used once per exchanged message.
-- It does not have to be confidential.
-- It is of size 'cryptoBoxNonceBytes'.
--
-- @since 0.0.1.0
newtype Nonce = Nonce (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance Nonce)

-- |
--
-- @since 0.0.1.0
instance Eq Nonce where
  (Nonce hk1) == (Nonce hk2) =
    foreignPtrEq hk1 hk2 cryptoBoxNonceBytes

-- |
--
-- @since 0.0.1.0
instance Ord Nonce where
  compare (Nonce hk1) (Nonce hk2) =
    foreignPtrOrd hk1 hk2 cryptoBoxNonceBytes

-- |
--
-- @since 0.0.1.0
instance Show Nonce where
  show = show . nonceToHexByteString

-- | Generate a new random nonce.
-- Only use it once per exchanged message.
--
-- Do not use this outside of ciphertext creation!
newNonce :: IO Nonce
newNonce = do
  (fPtr :: ForeignPtr CUChar) <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoBoxNonceBytes)
  Foreign.withForeignPtr fPtr $ \ptr ->
    randombytesBuf (Foreign.castPtr @CUChar @Word8 ptr) cryptoBoxNonceBytes
  pure $ Nonce fPtr

-- | Create a 'Nonce' from a hexadecimal-encoded 'StrictByteString' that you have obtained
-- on your own, usually from the network or disk.
--
-- @since 0.0.1.0
nonceFromHexByteString :: StrictByteString -> Either Text Nonce
nonceFromHexByteString hexNonce = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexNonce of
    Right bytestring ->
      BS.unsafeUseAsCStringLen bytestring $ \(outsideNoncePtr, _) -> do
        nonceForeignPtr <-
          BS.mallocByteString
            @CChar
            (fromIntegral cryptoBoxNonceBytes)
        Foreign.withForeignPtr nonceForeignPtr $ \noncePtr ->
          Foreign.copyArray
            noncePtr
            outsideNoncePtr
            (fromIntegral cryptoBoxNonceBytes)
        pure $ Right $ Nonce (Foreign.castForeignPtr @CChar @CUChar nonceForeignPtr)
    Left msg -> pure $ Left msg

-- | Convert a 'Nonce' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
nonceToHexByteString :: Nonce -> StrictByteString
nonceToHexByteString (Nonce nonceForeignPtr) =
  binaryToHex nonceForeignPtr cryptoBoxNonceBytes

-- | A ciphertext consisting of an encrypted message and an authentication tag.
--
-- @since 0.0.1.0
data CipherText = CipherText
  { messageLength :: CULLong
  , cipherTextForeignPtr :: ForeignPtr CUChar
  }

-- |
--
-- @since 0.0.1.0
instance Eq CipherText where
  (CipherText messageLength1 hk1) == (CipherText messageLength2 hk2) =
    let
      messageLength = messageLength1 == messageLength2
      content = foreignPtrEqConstantTime hk1 hk2 (fromIntegral messageLength1)
     in
      messageLength && content

-- |
--
-- @since 0.0.1.0
instance Ord CipherText where
  compare (CipherText messageLength1 hk1) (CipherText messageLength2 hk2) =
    let
      messageLength = compare messageLength1 messageLength2
      content = foreignPtrOrdConstantTime hk1 hk2 (fromIntegral messageLength1 + cryptoBoxMACBytes)
     in
      messageLength <> content

-- | ⚠️  Be prudent as to what you do with it!
--
-- @since 0.0.1.0
instance Display CipherText where
  displayBuilder = Builder.fromText . cipherTextToHexText

-- | ⚠️  Be prudent as to what you do with it!
--
-- @since 0.0.1.0
instance Show CipherText where
  show = BS.unpackChars . cipherTextToHexByteString

-- | Create a 'CipherText' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk. It must be a valid cipherText built from the concatenation
-- of the encrypted message and the authentication tag.
--
-- The input cipher text, once decoded from base16, must be at least of length
-- 'cryptoBoxMACBytes'.
--
-- @since 0.0.1.0
cipherTextFromHexByteString :: StrictByteString -> Either Text CipherText
cipherTextFromHexByteString hexByteString = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexByteString of
    Right bytestring ->
      if BS.length bytestring >= fromIntegral cryptoBoxMACBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideCipherTextPtr, outsideCipherTextLength) -> do
          cipherTextForeignPtr <- BS.mallocByteString @CChar outsideCipherTextLength
          Foreign.withForeignPtr cipherTextForeignPtr $ \cipherTextPtr ->
            Foreign.copyArray cipherTextPtr outsideCipherTextPtr outsideCipherTextLength
          pure $
            Right $
              CipherText
                (fromIntegral @Int @CULLong outsideCipherTextLength - fromIntegral @CSize @CULLong cryptoBoxMACBytes)
                (Foreign.castForeignPtr @CChar @CUChar cipherTextForeignPtr)
        else pure $ Left $ Text.pack "Cipher text is too short"
    Left msg -> error (Text.unpack msg)

-- | Convert a 'CipherText' to a hexadecimal-encoded 'Text'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
cipherTextToHexText :: CipherText -> Text
cipherTextToHexText = Base16.extractBase16 . Base16.encodeBase16 . cipherTextToBinary

-- | Convert a 'CipherText' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
cipherTextToHexByteString :: CipherText -> StrictByteString
cipherTextToHexByteString (CipherText messageLength fPtr) =
  binaryToHex fPtr (cryptoBoxMACBytes + fromIntegral messageLength)

-- | Convert a 'CipherText' to a binary 'StrictByteString'.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
cipherTextToBinary :: CipherText -> StrictByteString
cipherTextToBinary (CipherText messageLength fPtr) =
  BS.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral messageLength + fromIntegral cryptoBoxMACBytes)

-- | Create an authenticated 'CipherText' from a message, a 'SecretKey',
-- and a one-time cryptographic 'Nonce' that must never be re-used with the same
-- secret key to encrypt another message.
--
-- @since 0.0.1.0
encrypt
  :: StrictByteString
  -- ^ Message to encrypt.
  -> PublicKey
  -- ^ Public key of the recipient
  -> SecretKey
  -- ^ Secret key of the sender
  -> IO (Nonce, CipherText)
encrypt message (PublicKey publicKeyForeignPtr) (SecretKey secretKeyForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    (Nonce nonceForeignPtr) <- newNonce
    cipherTextForeignPtr <- Foreign.mallocForeignPtrBytes (cStringLen + fromIntegral cryptoBoxMACBytes)
    Foreign.withForeignPtr cipherTextForeignPtr $ \cipherTextPtr ->
      Foreign.withForeignPtr publicKeyForeignPtr $ \publicKeyPtr ->
        Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
          Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
            result <-
              cryptoBoxEasy
                cipherTextPtr
                (Foreign.castPtr @CChar @CUChar cString)
                (fromIntegral @Int @CULLong cStringLen)
                noncePtr
                publicKeyPtr
                secretKeyPtr
            when (result /= 0) $ throw EncryptionError
            let cipherText = CipherText (fromIntegral @Int @CULLong cStringLen) cipherTextForeignPtr
            pure (Nonce nonceForeignPtr, cipherText)

-- | Decrypt a 'CipherText' and authenticated message with the shared
-- secret key and the one-time cryptographic nonce.
--
-- @since 0.0.1.0
decrypt
  :: CipherText
  -- ^ Encrypted message you want to decrypt.
  -> PublicKey
  -- ^ Public key of the sender.
  -> SecretKey
  -- ^ Secret key of the recipient.
  -> Nonce
  -- ^ Nonce used for encrypting the original message.
  -> Maybe StrictByteString
decrypt
  CipherText{messageLength, cipherTextForeignPtr}
  (PublicKey publicKeyForeignPtr)
  (SecretKey secretKeyForeignPtr)
  (Nonce nonceForeignPtr) = unsafeDupablePerformIO $ do
    messagePtr <- Foreign.mallocBytes (fromIntegral @CULLong @Int messageLength)
    Foreign.withForeignPtr cipherTextForeignPtr $ \cipherTextPtr ->
      Foreign.withForeignPtr publicKeyForeignPtr $ \publicKeyPtr ->
        Foreign.withForeignPtr secretKeyForeignPtr $ \secretKeyPtr ->
          Foreign.withForeignPtr nonceForeignPtr $ \noncePtr -> do
            result <-
              cryptoBoxOpenEasy
                messagePtr
                cipherTextPtr
                (messageLength + fromIntegral @CSize @CULLong cryptoBoxMACBytes)
                noncePtr
                publicKeyPtr
                secretKeyPtr
            case result of
              (-1) -> pure Nothing
              _ -> do
                bsPtr <- Foreign.mallocBytes (fromIntegral messageLength)
                Foreign.copyBytes bsPtr messagePtr (fromIntegral messageLength)
                Just
                  <$> BS.unsafePackMallocCStringLen
                    (Foreign.castPtr @CUChar @CChar bsPtr, fromIntegral messageLength)

-- | Exception thrown upon error during the generation of
-- the key pair by 'newKeyPair'.
--
-- @since 0.0.1.0
data KeyPairGenerationException = KeyPairGenerationException
  deriving stock (Eq, Ord, Show)
  deriving anyclass (Exception)

-- | Exception thrown upon error during the encryption
-- of the message by 'encrypt'.
--
-- @since 0.0.1.0
data EncryptionError = EncryptionError
  deriving stock (Eq, Ord, Show)
  deriving anyclass (Exception)
