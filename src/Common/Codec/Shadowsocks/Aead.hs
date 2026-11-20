module Common.Codec.Shadowsocks.Aead (AeadDecoder (..), AeadEncoder (..), decodeChunks, encodeChunk, newAuthenticator) where

import Common.Codec.Chunk (ChunkSizeCodec (decodeSize, encodeSize, sizeBytes))
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind, newCipherMethod, nonceSize)
import Common.Crypto.Aead.Authenticator (Authenticator (..), open, seal)
import Common.Crypto.Aead.NonceGenerator (IncreasingNonceGenerator (IncreasingNonceGenerator))
import Common.Logger (trace_)
import Control.Monad.Catch (MonadThrow)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State.Strict (StateT, get, put, runStateT)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import GHC.Stack (HasCallStack)

newAuthenticator :: (MonadThrow m, HasCallStack) => CipherKind -> Key -> m (Authenticator IncreasingNonceGenerator)
newAuthenticator kind key = do
  method <- newCipherMethod kind key
  pure $ Authenticator method $ IncreasingNonceGenerator $ BA.replicate (nonceSize kind) 0xff

newtype AeadEncoder = AeadEncoder (Authenticator IncreasingNonceGenerator) deriving (Show)

data AeadDecoder = DecodeLength (Authenticator IncreasingNonceGenerator) | DecodeChunk (Authenticator IncreasingNonceGenerator) Int deriving (Show)

encodeChunk :: StrictByteString -> StateT AeadEncoder IO StrictByteString
encodeChunk plaintext = do
  AeadEncoder auth <- get
  let currentLength = B.length plaintext
  (chunkLengthBytes, auth') <- lift $ runStateT (encodeSize currentLength) auth
  (ciphertext, auth'') <- lift $ runStateT (seal plaintext) auth'
  lift $ trace_ "c.c.Aead" $ return $ "encode: C=" ++ show currentLength
  put $ AeadEncoder auth''
  return $ chunkLengthBytes <> ciphertext

type ChunkDecodeResult = Maybe (StrictByteString, StrictByteString)

decodeChunks :: StrictByteString -> StateT AeadDecoder IO ChunkDecodeResult
decodeChunks ciphertext = go ciphertext []
  where
    go leftover decodedChunks = do
      decoder <- get
      (result, decoder') <- lift $ runStateT (decodeChunk leftover) decoder
      case result of
        Nothing -> return $ case decodedChunks of
          [] -> Nothing
          [decoded] -> Just (leftover, decoded)
          _ -> Just (leftover, B.concat $ reverse decodedChunks)
        Just (leftover', decoded) -> put decoder' >> go leftover' (decoded : decodedChunks)

decodeChunk :: StrictByteString -> StateT AeadDecoder IO ChunkDecodeResult
decodeChunk ciphertext = do
  decoder <- get
  case decoder of
    DecodeLength auth
      | B.length ciphertext < sizeBytes auth -> return Nothing
      | otherwise -> do
          let (chunkLengthBytes, leftover) = B.splitAt (sizeBytes auth) ciphertext
          (chunkLength, auth') <- lift $ runStateT (decodeSize chunkLengthBytes) auth
          lift $ trace_ "c.c.Aead" $ return $ "decode: C=" ++ show chunkLength
          put $ DecodeChunk auth' chunkLength
          decodeChunk leftover
    DecodeChunk auth chunkLength
      | B.length ciphertext < chunkLength -> return Nothing
      | otherwise -> do
          let (ciphertext', leftover) = B.splitAt chunkLength ciphertext
          (plaintext, auth') <- lift $ runStateT (open ciphertext') auth
          put $ DecodeLength auth'
          return $ Just (leftover, plaintext)
