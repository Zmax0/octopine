{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Common.Codec.VMess.ShakeSizeParser (ShakeSizeParser, new) where

import Common.Codec.Chunk (ChunkSizeCodec (..), PaddingLengthGenerator (..))
import Common.Util (decodeWord16BE, encodeWord16BE, showBase64)
import Control.Monad.Trans.State.Strict (get, put)
import Crypto.Hash (Digest, SHAKE128 (SHAKE128), hashWith)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.Proxy (Proxy (..))
import GHC.Bits (xor)
import GHC.TypeNats (SomeNat (..), someNatVal)

data ShakeSizeParser = ShakeSizeParser
  { nonce :: !StrictByteString,
    cache :: !StrictByteString,
    offset :: !Int,
    totalOffset :: !Int
  }

new :: StrictByteString -> ShakeSizeParser
new nonce' = ShakeSizeParser nonce' (_shake128 nonce' initialCapacity) 0 0

initialCapacity :: Int
initialCapacity = 32 -- can be used 16 times

growStep :: Int
growStep = 64

_shake128 :: StrictByteString -> Int -> StrictByteString
_shake128 nonce' byteLen =
  case someNatVal (fromIntegral (byteLen * 8)) of
    SomeNat (_ :: Proxy bits) -> BA.convert (hashWith (SHAKE128 :: SHAKE128 bits) nonce' :: Digest (SHAKE128 bits))

next :: ShakeSizeParser -> (Int, ShakeSizeParser)
next parser =
  let parser'
        | B.length (cache parser) - offset parser >= 2 = parser
        | otherwise =
            let unread = B.drop (offset parser) (cache parser)
                currentTotalLen = totalOffset parser - offset parser + B.length (cache parser)
                targetLen = currentTotalLen + growStep
                delta = B.drop currentTotalLen (_shake128 (nonce parser) targetLen)
             in parser {cache = unread <> delta, offset = 0}
      offset' = offset parser'
      value = _readWord16BE (cache parser') offset'
   in (value, parser' {offset = offset' + 2, totalOffset = totalOffset parser' + 2})

_readWord16BE :: StrictByteString -> Int -> Int
_readWord16BE bytes off =
  let hi = fromIntegral $ B.index bytes off
      lo = fromIntegral $ B.index bytes (off + 1)
   in hi * 256 + lo

instance ChunkSizeCodec ShakeSizeParser where
  sizeBytes _ = 2
  encodeSize length' = do
    parser <- get
    let (value, parser') = next parser
    put parser'
    return $ encodeWord16BE $ value `xor` length'
  decodeSize msg = do
    parser <- get
    let (next', parser') = next parser
    put parser'
    return $ next' `xor` decodeWord16BE msg

instance PaddingLengthGenerator ShakeSizeParser where
  nextPaddingLength = do
    parser <- get
    let (next', parser') = next parser
    put parser'
    return $ next' `mod` 64

instance Show ShakeSizeParser where
  show parser =
    "[Nonce = "
      ++ showBase64 (nonce parser)
      ++ ", Cache = "
      ++ showBase64 (cache parser)
      ++ ", Offset = "
      ++ show (totalOffset parser)
      ++ ", CacheOffset = "
      ++ show (offset parser)
      ++ "]"
