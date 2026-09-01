module Common.Lang.Go (fnv1a32) where

import Data.Bits (Bits (xor))
import qualified Data.ByteString as B
import Data.Word (Word32)

-- 32 bits FNV-1a hash function using golang implementation
fnv1a32 :: B.ByteString -> Word32
fnv1a32 = B.foldl' step fnv1a32OffsetBasis
  where
    step h byte = (h `xor` fromIntegral byte) * fnv1a32Prime

fnv1a32OffsetBasis :: Word32
fnv1a32OffsetBasis = 0x811c9dc5

fnv1a32Prime :: Word32
fnv1a32Prime = 0x01000193
