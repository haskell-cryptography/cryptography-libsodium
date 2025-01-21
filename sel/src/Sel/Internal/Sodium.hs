{-# LANGUAGE ImportQualifiedPost #-}

module Sel.Internal.Sodium where

import Control.Monad.Trans.Class (lift)
import Data.ByteString (StrictByteString)
import Data.ByteString qualified as ByteString
import Foreign (ForeignPtr)
import Foreign.C (CSize, CUChar)
import LibSodium.Bindings.Utils
import Sel.Internal.Scoped
import Sel.Internal.Scoped.Foreign
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Convert a byte array to a hexadecimal-encoded 'StrictByteString' in constant time.
--
-- /See:/ [@sodium_bin2hex@](https://libsodium.gitbook.io/doc/helpers#hexadecimal-encoding-decoding)
--
-- @since 0.0.3.0
binaryToHex :: ForeignPtr CUChar -> CSize -> StrictByteString
binaryToHex fPtr size = unsafeDupablePerformIO . use $ do
  let hexLength = size * 2 + 1
  hexPtr <- foreignPtr =<< mallocForeignPtrBytes (fromIntegral hexLength)
  ptr <- foreignPtr fPtr
  lift $ ByteString.packCString =<< sodiumBin2Hex hexPtr hexLength ptr size
