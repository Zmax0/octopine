module Common.Codec.Chunk (ChunkSizeCodec (..), EmptyChunkSizeParser (EmptyChunkSizeParser), PlainChunkSizeParser (PlainChunkSizeParser), PaddingLengthGenerator (..), EmptyPaddingLengthGenerator (EmptyPaddingLengthGenerator)) where

import Common.Util (decodeWord16BE, encodeWord16BE)
import Control.Monad.Trans.State.Strict (State)
import Data.ByteString (StrictByteString)

class ChunkSizeCodec c where
  sizeBytes :: c -> Int
  encodeSize :: Int -> State c StrictByteString
  decodeSize :: StrictByteString -> State c Int

data EmptyChunkSizeParser = EmptyChunkSizeParser deriving (Show)

instance ChunkSizeCodec EmptyChunkSizeParser where
  sizeBytes _ = 0 :: Int
  encodeSize = error "unsupported"
  decodeSize = error "unsupported"

data PlainChunkSizeParser = PlainChunkSizeParser deriving (Show)

instance ChunkSizeCodec PlainChunkSizeParser where
  sizeBytes _ = 2 :: Int
  encodeSize = return . encodeWord16BE
  decodeSize = return . decodeWord16BE

class PaddingLengthGenerator g where
  nextPaddingLength :: State g Int

data EmptyPaddingLengthGenerator = EmptyPaddingLengthGenerator deriving (Show)

instance PaddingLengthGenerator EmptyPaddingLengthGenerator where
  nextPaddingLength = return 0
