{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE MultiWayIf #-}

module Sel.Internal where

import Foreign (Ptr)
import Foreign.C.Types (CInt (CInt), CSize (CSize))
import Foreign.ForeignPtr (ForeignPtr, withForeignPtr)
import LibSodium.Bindings.SecureMemory (sodiumFree, sodiumMalloc)

-- | This calls to C's @memcmp@ function, used in lieu of
-- libsodium's @memcmp@ in cases when the return code is necessary.
foreign import capi unsafe "string.h memcmp"
  memcmp :: Ptr a -> Ptr b -> CSize -> IO CInt

-- | Compare if the contents of two @ForeignPtr@s are equal.
foreignPtrEq :: ForeignPtr a -> ForeignPtr a -> CSize -> IO Bool
foreignPtrEq fptr1 fptr2 size =
  withForeignPtr fptr1 $ \p ->
    withForeignPtr fptr2 $ \q ->
      do
        result <- memcmp p q size
        return $ 0 == result

-- | Compare the contents of two @ForeignPtr@s using lexicographical ordering.
foreignPtrOrd :: ForeignPtr a -> ForeignPtr a -> CSize -> IO Ordering
foreignPtrOrd fptr1 fptr2 size =
  withForeignPtr fptr1 $ \p ->
    withForeignPtr fptr2 $ \q ->
      do
        result <- memcmp p q size
        return $
          if
              | result == 0 -> EQ
              | result < 0 -> LT
              | otherwise -> GT

-- | Securely allocate an amount of memory with 'sodiumMalloc' and pass
-- a pointer to the region to the provided action.
-- The region is deallocated with 'sodiumFree'.
allocateWith :: CSize -> (Ptr a -> IO b) -> IO b
allocateWith size action = do
  !ptr <- sodiumMalloc size
  !result <- action ptr
  sodiumFree ptr
  pure result
