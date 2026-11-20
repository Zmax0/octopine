module Common.Codec.Chunk (ChunkSizeCodec (..), EmptyChunkSizeParser (EmptyChunkSizeParser), PlainChunkSizeParser (PlainChunkSizeParser), PaddingLengthGenerator (..), EmptyPaddingLengthGenerator (EmptyPaddingLengthGenerator)) where

import Common.Exception (AppExceptionKind (InvariantError), throwApp)
import Common.Util (decodeWord16BE, encodeWord16BE)
import Control.Monad.Catch (MonadThrow)
import Control.Monad.Trans.State.Strict (State, StateT)
import Data.ByteString (StrictByteString)
import GHC.Stack (HasCallStack)

class ChunkSizeCodec c where
  sizeBytes :: c -> Int
  encodeSize :: (MonadThrow m, HasCallStack) => Int -> StateT c m StrictByteString
  decodeSize :: (MonadThrow m, HasCallStack) => StrictByteString -> StateT c m Int

data EmptyChunkSizeParser = EmptyChunkSizeParser deriving (Show)

instance ChunkSizeCodec EmptyChunkSizeParser where
  sizeBytes _ = 0 :: Int
  encodeSize _ = throwApp InvariantError "empty chunk parser cannot encode size"
  decodeSize _ = throwApp InvariantError "empty chunk parser cannot decode size"

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
