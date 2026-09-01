module Common.Crypto.Aead.NonceGenerator (NonceGenerator (generate), IncreasingNonceGenerator (IncreasingNonceGenerator), CountingNonceGenerator (CountingNonceGenerator), generateT) where

import Control.Monad (when)
import Control.Monad.Trans.State.Strict (State, get, put)
import Data.Bits ((.&.), (.>>.))
import Data.ByteArray (Bytes)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Foreign (Ptr, Storable (peek, poke), Word8, plusPtr)
import GHC.Word (Word16)

class NonceGenerator a where
  generate :: State a Bytes

newtype IncreasingNonceGenerator = IncreasingNonceGenerator Bytes deriving (Show)

instance NonceGenerator IncreasingNonceGenerator where
  generate = do
    IncreasingNonceGenerator nonce <- get
    let nonce' = _incrementNonce nonce 0
    put $ IncreasingNonceGenerator nonce'
    return nonce'

_incrementNonce :: Bytes -> Int -> Bytes
_incrementNonce bytes offset = BA.copyAndFreeze bytes $ \s ->
  let end = s `plusPtr` BA.length bytes
   in loop end (s `plusPtr` offset)
  where
    loop :: Ptr Word8 -> Ptr Word8 -> IO ()
    loop end p
      | p == end = return ()
      | otherwise = do
          r <- (+) 1 <$> peek p
          poke p r
          when (r == 0) $ loop end (p `plusPtr` 1)

data CountingNonceGenerator = CountingNonceGenerator !Word16 !Int deriving (Show)

-- | (original nonce, generated nonce)
generateT :: StrictByteString -> State CountingNonceGenerator (StrictByteString, StrictByteString)
generateT nonce = do
  CountingNonceGenerator count size <- get
  let bytes = B.pack [fromIntegral (count .>>. 8), fromIntegral (count .&. 0xff)]
      nonce' = bytes <> B.drop 2 nonce
  put $ CountingNonceGenerator (count + 1) size
  return (nonce', B.take size nonce')
