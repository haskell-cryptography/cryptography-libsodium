{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.SecretKey.EncryptedStream where

import Data.ByteString (StrictByteString)
import Data.Either
import Data.Traversable
import Test.Tasty
import Test.Tasty.HUnit

import Sel.SecretKey.EncryptedStream

spec :: TestTree
spec =
  testGroup
    "Encrypted Stream"
    [ testCase "Encrypt and decrypt a stream" testStream
    ]

testStream :: Assertion
testStream = do
  let messages = ["King", "of", "Kings", "am", "I,", "Osymandias."] :: [StrictByteString]
  let encryptChunks :: Multipart s -> [StrictByteString] -> IO [CipherText]
      encryptChunks _ [] = pure []
      encryptChunks state [x] = do
        result <- pushToStream state x Nothing Final
        case result of
          Left err -> assertFailure (show err)
          Right ct -> pure [ct]
      encryptChunks state (x : xs) = do
        result <- pushToStream state x Nothing Message
        case result of
          Left err -> assertFailure (show err)
          Right ct -> do
            rest <- encryptChunks state xs
            pure $ ct : rest
  (header, secretKey, cipherTexts) <- encryptStream $ \state -> do
    encryptChunks state messages

  decryptionResult' :: [Either EncryptedStreamError StreamResult] <- decryptStream (header, secretKey) $ \statePtr -> do
    forM cipherTexts $ \ct -> pullFromStream statePtr ct

  let decryptionResult = streamMessage <$> rights decryptionResult'
  assertEqual
    "Message is well-opened with the correct key and nonce"
    messages
    decryptionResult
