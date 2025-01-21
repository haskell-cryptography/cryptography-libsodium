{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RoleAnnotations #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- Module: Sel.HMAC.SHA512_256
-- Description: HMAC-SHA-512-256
-- Maintainer: The Haskell Cryptography Group
-- Portability: GHC only
module Sel.HMAC.SHA512_256
  ( -- ** Introduction
    -- $introduction

    -- ** Usage
    -- $usage

    -- ** Operations

    -- *** Authenticating a single messsage
    authenticate

    -- *** Authenticating a multi-part message
  , Multipart
  , withMultipart
  , updateMultipart

    -- *** Verifying a message
  , verify

    -- ** Authentication key
  , AuthenticationKey
  , newAuthenticationKey
  , authenticationKeyFromHexByteString
  , unsafeAuthenticationKeyToHexByteString
  , unsafeAuthenticationKeyToBinary

    -- ** Authentication tag
  , AuthenticationTag
  , authenticationTagToHexByteString
  , authenticationTagToBinary
  , authenticationTagFromHexByteString
  ) where

--

import Control.Monad (void, when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.Base16.Types as Base16
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Kind (Type)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Display
import Foreign (ForeignPtr, Ptr, Word8)
import qualified Foreign
import Foreign.C (CChar, CSize, CUChar, CULLong)
import Foreign.C.Error (throwErrno)
import System.IO.Unsafe (unsafeDupablePerformIO)

import LibSodium.Bindings.SHA2
  ( CryptoAuthHMACSHA512256State
  , cryptoAuthHMACSHA512256
  , cryptoAuthHMACSHA512256Bytes
  , cryptoAuthHMACSHA512256Final
  , cryptoAuthHMACSHA512256Init
  , cryptoAuthHMACSHA512256KeyBytes
  , cryptoAuthHMACSHA512256Keygen
  , cryptoAuthHMACSHA512256StateBytes
  , cryptoAuthHMACSHA512256Update
  , cryptoAuthHMACSHA512256Verify
  )
import LibSodium.Bindings.SecureMemory (finalizerSodiumFree, sodiumMalloc)
import Sel.Internal (allocateWith, foreignPtrEqConstantTime, foreignPtrOrdConstantTime)
import Sel.Internal.Sodium (binaryToHex)

-- $introduction
-- The 'authenticate' function computes an authentication tag for a message and a secret key,
-- and provides a way to verify that a given tag is valid for a given message and a key.
--
-- The function computing the tag deterministic: the same @(message, key)@ tuple will always
-- produce the same output. However, even if the message is public, knowing the key is required
-- in order to be able to compute a valid tag.
-- Therefore, the key should remain confidential. The tag, however, can be public.

-- $usage
--
-- > import Sel.HMAC.SHA512_256 qualified as HMAC
-- > import Sel (secureMain)
-- >
-- > main = secureMain $ do
-- >   -- The parties agree on a shared secret key
-- >   authKey <- HMAC.newAuthenticationKey
-- >   -- An authentication tag is computed for the message by the server
-- >   let message = ("Hello, world!" :: StrictByteString)
-- >   tag <- HMAC.authenticate message
-- >   -- The server sends the message and its authentication tag
-- >   -- […]
-- >   -- The recipient of the message uses the shared secret to validate the message's tag
-- >   HMAC.verify tag authKey message
-- >   -- => True

-- | Compute an authentication tag for a message with a secret key shared by all parties.
--
-- @since 0.0.1.0
authenticate
  :: StrictByteString
  -- ^ Message to authenticate
  -> AuthenticationKey
  -- ^ Secret key for authentication
  -> IO AuthenticationTag
  -- ^ Cryptographic tag for authentication
authenticate message (AuthenticationKey authenticationKeyForeignPtr) =
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    authenticationTagForeignPtr <-
      Foreign.mallocForeignPtrBytes
        (fromIntegral cryptoAuthHMACSHA512256Bytes)
    Foreign.withForeignPtr authenticationTagForeignPtr $ \authTagPtr ->
      Foreign.withForeignPtr authenticationKeyForeignPtr $ \authKeyPtr ->
        void $
          cryptoAuthHMACSHA512256
            authTagPtr
            (Foreign.castPtr @CChar @CUChar cString)
            (fromIntegral @Int @CULLong cStringLen)
            authKeyPtr
    pure $ AuthenticationTag authenticationTagForeignPtr

-- ** Authenticating a multi-part message

-- | 'Multipart' is a cryptographic context for streaming hashing.
-- This API can be used when a message is too big to fit
-- in memory or when the message is received in portions.
--
-- Use it like this:
--
-- >>> secretKey <- HMAC.newSecreKey
-- >>> hash <- HMAC.withMultipart secretKey $ \multipartState -> do -- we are in MonadIO
-- ...   message1 <- getMessage
-- ...   HMAC.updateMultipart multipartState message1
-- ...   message2 <- getMessage
-- ...   HMAC.updateMultipart multipartState message2
--
-- @since 0.0.1.0
newtype Multipart s = Multipart (Ptr CryptoAuthHMACSHA512256State)

type role Multipart nominal

-- | Perform streaming hashing with a 'Multipart' cryptographic context.
--
-- Use 'HMAC.updateMultipart' within the continuation.
--
-- The context is safely allocated first, then the continuation is run
-- and then it is deallocated after that.
--
-- @since 0.0.1.0
withMultipart
  :: forall (a :: Type) (m :: Type -> Type)
   . MonadIO m
  => AuthenticationKey
  -> (forall s. Multipart s -> m a)
  -- ^ Continuation that gives you access to a 'Multipart' cryptographic context
  -> m AuthenticationTag
withMultipart (AuthenticationKey secretKeyForeignPtr) actions = do
  allocateWith cryptoAuthHMACSHA512256StateBytes $ \statePtr -> do
    liftIO $ Foreign.withForeignPtr secretKeyForeignPtr $ \keyPtr ->
      cryptoAuthHMACSHA512256Init statePtr keyPtr cryptoAuthHMACSHA512256KeyBytes
    let part = Multipart statePtr
    actions part
    finaliseMultipart part

-- | Compute the 'AuthenticationTag' of all the portions that were fed to the cryptographic context.
--
--  this function is only used within 'withMultipart'
--
--  @since 0.0.1.0
finaliseMultipart :: MonadIO m => Multipart s -> m AuthenticationTag
finaliseMultipart (Multipart statePtr) = do
  authenticatorForeignPtr <- liftIO $ Foreign.mallocForeignPtrBytes (fromIntegral cryptoAuthHMACSHA512256Bytes)
  liftIO $ Foreign.withForeignPtr authenticatorForeignPtr $ \(authenticatorPtr :: Ptr CUChar) ->
    void $
      cryptoAuthHMACSHA512256Final
        statePtr
        authenticatorPtr
  pure $ AuthenticationTag authenticatorForeignPtr

-- | Add a message portion to be hashed.
--
-- This function should be used within 'withMultipart'.
--
-- @since 0.0.1.0
updateMultipart :: Multipart s -> StrictByteString -> IO ()
updateMultipart (Multipart statePtr) message = do
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) -> do
    let messagePtr = Foreign.castPtr @CChar @CUChar cString
    let messageLen = fromIntegral @Int @CULLong cStringLen
    void $
      cryptoAuthHMACSHA512256Update
        statePtr
        messagePtr
        messageLen

-- | Verify that the tag is valid for the provided message and secret key.
--
-- @since 0.0.1.0
verify
  :: AuthenticationTag
  -> AuthenticationKey
  -> StrictByteString
  -> Bool
verify (AuthenticationTag tagForeignPtr) (AuthenticationKey keyForeignPtr) message = unsafeDupablePerformIO $
  BS.unsafeUseAsCStringLen message $ \(cString, cStringLen) ->
    Foreign.withForeignPtr tagForeignPtr $ \authTagPtr ->
      Foreign.withForeignPtr keyForeignPtr $ \authKeyPtr -> do
        result <-
          cryptoAuthHMACSHA512256Verify
            authTagPtr
            (Foreign.castPtr @CChar @CUChar cString)
            (fromIntegral @Int @CULLong cStringLen)
            authKeyPtr
        pure $ result == 0

-- | A secret authentication key of size 'cryptoAuthHMACSHA512256Bytes'.
--
-- @since 0.0.1.0
newtype AuthenticationKey = AuthenticationKey (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
      -- > display authenticatonKey == "[REDACTED]"
    )
    via (OpaqueInstance "[REDACTED]" AuthenticationKey)

-- |
--
-- @since 0.0.1.0
instance Eq AuthenticationKey where
  (AuthenticationKey hk1) == (AuthenticationKey hk2) =
    foreignPtrEqConstantTime hk1 hk2 cryptoAuthHMACSHA512256KeyBytes

-- |
--
-- @since 0.0.1.0
instance Ord AuthenticationKey where
  compare (AuthenticationKey hk1) (AuthenticationKey hk2) =
    foreignPtrOrdConstantTime hk1 hk2 cryptoAuthHMACSHA512256KeyBytes

-- | > show authenticationKey == "[REDACTED]"
--
-- @since 0.0.1.0
instance Show AuthenticationKey where
  show _ = "[REDACTED]"

-- | Generate a new random secret key of size 'cryptoAuthHMACSHA512256KeyBytes'.
--
-- @since 0.0.1.0
newAuthenticationKey :: IO AuthenticationKey
newAuthenticationKey = newAuthenticationKeyWith cryptoAuthHMACSHA512256Keygen

-- | Prepare memory for a 'AuthenticationKey' and use the provided action to fill it.
--
-- Memory is allocated with 'LibSodium.Bindings.SecureMemory.sodiumMalloc'
-- (see the note attached there).
-- A finalizer is run when the key is goes out of scope.
newAuthenticationKeyWith :: (Foreign.Ptr CUChar -> IO ()) -> IO AuthenticationKey
newAuthenticationKeyWith action = do
  ptr <- sodiumMalloc cryptoAuthHMACSHA512256KeyBytes
  when (ptr == Foreign.nullPtr) $ do
    throwErrno "sodium_malloc"

  fPtr <- Foreign.newForeignPtr_ ptr
  Foreign.addForeignPtrFinalizer finalizerSodiumFree fPtr
  action ptr
  pure $ AuthenticationKey fPtr

-- | Create an 'AuthenticationKey' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- The input secret key, once decoded from base16, must be of length
-- 'cryptoAuthHMACSHA512256Bytes'.
--
-- @since 0.0.1.0
authenticationKeyFromHexByteString :: StrictByteString -> Either Text AuthenticationKey
authenticationKeyFromHexByteString hexKey = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexKey of
    Right bytestring ->
      if BS.length bytestring == fromIntegral cryptoAuthHMACSHA512256KeyBytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideAuthenticationKeyPtr, _) ->
          fmap Right $
            newAuthenticationKeyWith $ \authenticationKeyPtr ->
              Foreign.copyArray
                (Foreign.castPtr @CUChar @CChar authenticationKeyPtr)
                outsideAuthenticationKeyPtr
                (fromIntegral cryptoAuthHMACSHA512256KeyBytes)
        else pure $ Left $ Text.pack "Authentication Key is too short"
    Left msg -> pure $ Left msg

-- | Convert a 'AuthenticationKey to a hexadecimal-encoded 'StrictByteString'.
--
-- This format is useful if you need conversion to base32 or base64.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeAuthenticationKeyToBinary :: AuthenticationKey -> StrictByteString
unsafeAuthenticationKeyToBinary (AuthenticationKey authenticationKeyForeignPtr) =
  Base16.extractBase16 . Base16.encodeBase16' $
    BS.fromForeignPtr0
      (Foreign.castForeignPtr @CUChar @Word8 authenticationKeyForeignPtr)
      (fromIntegral @CSize @Int cryptoAuthHMACSHA512256KeyBytes)

-- | Convert a 'AuthenticationKey to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- ⚠️  Be prudent as to where you store it!
--
-- @since 0.0.1.0
unsafeAuthenticationKeyToHexByteString :: AuthenticationKey -> StrictByteString
unsafeAuthenticationKeyToHexByteString (AuthenticationKey authenticationKeyForeignPtr) =
  binaryToHex authenticationKeyForeignPtr cryptoAuthHMACSHA512256KeyBytes

-- | A secret authentication key of size 'cryptoAuthHMACSHA512256Bytes'.
--
-- @since 0.0.1.0
newtype AuthenticationTag = AuthenticationTag (ForeignPtr CUChar)
  deriving
    ( Display
      -- ^ @since 0.0.1.0
    )
    via (ShowInstance AuthenticationTag)

-- |
--
-- @since 0.0.1.0
instance Eq AuthenticationTag where
  (AuthenticationTag hk1) == (AuthenticationTag hk2) =
    foreignPtrEqConstantTime hk1 hk2 cryptoAuthHMACSHA512256Bytes

-- |
--
-- @since 0.0.1.0
instance Ord AuthenticationTag where
  compare (AuthenticationTag hk1) (AuthenticationTag hk2) =
    foreignPtrOrdConstantTime hk1 hk2 cryptoAuthHMACSHA512256Bytes

-- |
--
-- @since 0.0.1.0
instance Show AuthenticationTag where
  show = BS.unpackChars . authenticationTagToHexByteString

-- | Convert an 'AuthenticationTag' to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- @since 0.0.1.0
authenticationTagToHexByteString :: AuthenticationTag -> StrictByteString
authenticationTagToHexByteString (AuthenticationTag authenticationTagForeignPtr) =
  binaryToHex authenticationTagForeignPtr cryptoAuthHMACSHA512256Bytes

-- | Convert an 'AuthenticationTag' to a binary 'StrictByteString'.
--
-- @since 0.0.1.0
authenticationTagToBinary :: AuthenticationTag -> StrictByteString
authenticationTagToBinary (AuthenticationTag fPtr) =
  BS.fromForeignPtr0
    (Foreign.castForeignPtr fPtr)
    (fromIntegral cryptoAuthHMACSHA512256Bytes)

-- | Create an 'AuthenticationTag' from a binary 'StrictByteString' that you have obtained on your own,
-- usually from the network or disk.
--
-- The input secret key, once decoded from base16, must be of length
-- 'cryptoAuthHMACSHA512256Bytes'.
--
-- @since 0.0.1.0
authenticationTagFromHexByteString :: StrictByteString -> Either Text AuthenticationTag
authenticationTagFromHexByteString hexTag = unsafeDupablePerformIO $
  case Base16.decodeBase16Untyped hexTag of
    Right bytestring ->
      if BS.length bytestring >= fromIntegral cryptoAuthHMACSHA512256Bytes
        then BS.unsafeUseAsCStringLen bytestring $ \(outsideTagPtr, outsideTagLength) -> do
          hashForeignPtr <- BS.mallocByteString @CChar outsideTagLength -- The foreign pointer that will receive the hash data.
          Foreign.withForeignPtr hashForeignPtr $ \hashPtr ->
            -- We copy bytes from 'outsideTagPtr' to 'hashPtr'.
            Foreign.copyArray hashPtr outsideTagPtr outsideTagLength
          pure $
            Right $
              AuthenticationTag
                (Foreign.castForeignPtr @CChar @CUChar hashForeignPtr)
        else pure $ Left $ Text.pack "Authentication tag is too short"
    Left msg -> pure $ Left msg
