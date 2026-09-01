module Common.Codec.Shadowsocks.Aead (AeadDecoder (..), AeadEncoder (..), decodeChunks, encodeChunk, newAuthenticator) where

import Common.Codec.Chunk (ChunkSizeCodec (decodeSize, encodeSize, sizeBytes))
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind, newCipherMethod, nonceSize)
import Common.Crypto.Aead.Authenticator (Authenticator (..), open, seal)
import Common.Crypto.Aead.NonceGenerator (IncreasingNonceGenerator (IncreasingNonceGenerator))
import Common.Logger (trace_)
import Control.Exception (SomeException)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State.Strict (StateT, get, put, runState)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B

newAuthenticator :: CipherKind -> Key -> Authenticator IncreasingNonceGenerator
newAuthenticator kind key = Authenticator (newCipherMethod kind key) $ IncreasingNonceGenerator $ BA.replicate (nonceSize kind) 0xff

newtype AeadEncoder = AeadEncoder (Authenticator IncreasingNonceGenerator) deriving (Show)

data AeadDecoder = DecodeLength (Authenticator IncreasingNonceGenerator) | DecodeChunk (Authenticator IncreasingNonceGenerator) Int deriving (Show)

encodeChunk :: StrictByteString -> StateT AeadEncoder IO StrictByteString
encodeChunk plaintext = do
  AeadEncoder auth <- get
  let currentLength = B.length plaintext
      (chunkLengthBytes, auth') = runState (encodeSize currentLength) auth
      (ciphertext, auth'') = runState (seal plaintext) auth'
  lift $ trace_ "c.c.Aead" $ return $ "encode: C=" ++ show currentLength
  put $ AeadEncoder auth''
  return $ chunkLengthBytes <> ciphertext

type ChunkDecodeResult = Either SomeException (Maybe (StrictByteString, StrictByteString))

decodeChunks :: StrictByteString -> StateT AeadDecoder IO ChunkDecodeResult
decodeChunks ciphertext = go ciphertext []
  where
    go leftover decodedChunks = do
      result <- decodeChunk leftover
      case result of
        Left exception -> return $ Left exception
        Right Nothing -> return $ Right $ case decodedChunks of
          [] -> Nothing
          [decoded] -> Just (leftover, decoded)
          _ -> Just (leftover, B.concat $ reverse decodedChunks)
        Right (Just (leftover', decoded))
          | B.null decoded -> go leftover' decodedChunks
          | otherwise -> go leftover' (decoded : decodedChunks)

decodeChunk :: StrictByteString -> StateT AeadDecoder IO ChunkDecodeResult
decodeChunk ciphertext = do
  decoder <- get
  case decoder of
    DecodeLength auth
      | B.length ciphertext < sizeBytes auth -> return $ Right Nothing
      | otherwise -> do
          let (chunkLengthBytes, leftover) = B.splitAt (sizeBytes auth) ciphertext
              (chunkLength, auth') = runState (decodeSize chunkLengthBytes) auth
          lift $ trace_ "c.c.Aead" $ return $ "decode: C=" ++ show chunkLength
          put $ DecodeChunk auth' chunkLength
          decodeChunk leftover
    DecodeChunk auth chunkLength
      | B.length ciphertext < chunkLength -> return $ Right Nothing
      | otherwise -> do
          let (ciphertext', leftover) = B.splitAt chunkLength ciphertext
              (plaintext, auth') = runState (open ciphertext') auth
          put $ DecodeLength auth'
          return $ Right $ Just (leftover, plaintext)
