{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Common.Codec.VMess.AeadEncoder (AeadEncoder (..), encode) where

import Common.Codec.Chunk (PaddingLengthGenerator (nextPaddingLength))
import qualified Common.Codec.Chunk as Chunk
import Common.Codec.VMess.Aead (Authenticator, ChunkNonce, LengthNonce, encodeSize, overhead, seal, sizeBytes)
import Common.Codec.VMess.Session (Session)
import Common.Codec.VMess.ShakeSizeParser (ShakeSizeParser)
import Common.Dice (rollBytes)
import Common.Logger (loggers, trace_)
import Control.Monad.IO.Class (MonadIO (liftIO))
import Control.Monad.Trans.State.Strict (StateT, get, put, runState)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Formatting (format, int, (%))

$(loggers "c.c.v.AeadEncoder" ['trace_])

data AeadEncoder
  = Default Authenticator
  | AuthLength !Authenticator !Authenticator
  | AuthLengthPadding !Authenticator !Authenticator !ShakeSizeParser
  | ShakeLength !Authenticator !ShakeSizeParser
  | ShakeLengthPadding !Authenticator !ShakeSizeParser
  deriving (Show)

payloadLimit :: Int
payloadLimit = 16301

maxPaddingLength :: Int
maxPaddingLength = 64

chunkPlaintextLimit :: AeadEncoder -> Int
chunkPlaintextLimit (Default auth) = chunkLimit (overhead auth) 0 0
chunkPlaintextLimit (AuthLength auth chunk) = chunkLimit (overhead auth) (sizeBytes chunk) 0
chunkPlaintextLimit (AuthLengthPadding auth chunk _) = chunkLimit (overhead auth) (sizeBytes chunk) maxPaddingLength
chunkPlaintextLimit (ShakeLength auth chunk) = chunkLimit (overhead auth) (Chunk.sizeBytes chunk) 0
chunkPlaintextLimit (ShakeLengthPadding auth padding) = chunkLimit (overhead auth) (Chunk.sizeBytes padding) maxPaddingLength

chunkLimit :: Int -> Int -> Int -> Int
chunkLimit overhead' sizeBytes' maxPadding' = payloadLimit - overhead' - sizeBytes' - maxPadding'

encode :: (MonadIO m) => StrictByteString -> Session -> LengthNonce -> ChunkNonce -> StateT AeadEncoder m (StrictByteString, Session)
encode plaintext session lengthNonce chunkNonce = do
  get >>= \case
    Default _ -> encodeChunk plaintext session lengthNonce chunkNonce
    encoder -> go (chunkPlaintextLimit encoder) plaintext session []
  where
    go limit remaining session' acc
      | B.length remaining <= limit = do
          (encoded, session'') <- encodeChunk remaining session' lengthNonce chunkNonce
          return (B.concat $ reverse (encoded : acc), session'')
      | otherwise = do
          let (piece, rest) = B.splitAt limit remaining
          (encoded, session'') <- encodeChunk piece session' lengthNonce chunkNonce
          go limit rest session'' (encoded : acc)

encodeChunk :: (MonadIO m) => StrictByteString -> Session -> LengthNonce -> ChunkNonce -> StateT AeadEncoder m (StrictByteString, Session)
encodeChunk plaintext session lengthNonce chunkNonce = do
  get >>= \case
    Default auth -> do
      let ((ciphertext, session'), auth') = runState (seal plaintext session lengthNonce) auth
      put $ Default auth'
      return (ciphertext, session')
    AuthLength auth chunk -> do
      let currentLength = B.length plaintext
          ((chunkLengthBytes, session'), chunk') = runState (encodeSize currentLength session lengthNonce) chunk
          ((ciphertext, session''), auth') = runState (seal plaintext session' chunkNonce) auth
      liftIO $ _trace_ $ format ("encode: C=" % int) currentLength
      put $ AuthLength auth' chunk'
      return (chunkLengthBytes <> ciphertext, session'')
    AuthLengthPadding auth chunk padding -> do
      let currentLength = B.length plaintext
          (paddingLength, padding') = runState nextPaddingLength padding
          ((chunkLengthBytes, session'), chunk') = runState (encodeSize (currentLength + paddingLength) session lengthNonce) chunk
          ((ciphertext, session''), auth') = runState (seal plaintext session' chunkNonce) auth
      liftIO $ _trace_ $ format ("encode: C=" % int % "|P=" % int) currentLength paddingLength
      paddingBytes <- liftIO $ rollBytes paddingLength
      put $ AuthLengthPadding auth' chunk' padding'
      return (chunkLengthBytes <> ciphertext <> paddingBytes, session'')
    ShakeLength auth chunk -> do
      let currentLength = B.length plaintext
          (chunkLengthBytes, chunk') = runState (Chunk.encodeSize (currentLength + overhead auth)) chunk
          ((ciphertext, session'), auth') = runState (seal plaintext session chunkNonce) auth
      liftIO $ _trace_ $ format ("encode: C=" % int) currentLength
      put $ ShakeLength auth' chunk'
      return (chunkLengthBytes <> ciphertext, session')
    ShakeLengthPadding auth padding -> do
      let currentLength = B.length plaintext
          (paddingLength, padding') = runState nextPaddingLength padding
          (chunkLengthBytes, padding'') = runState (Chunk.encodeSize $ currentLength + overhead auth + paddingLength) padding'
          ((ciphertext, session'), auth') = runState (seal plaintext session chunkNonce) auth
      liftIO $ _trace_ $ format ("encode: C=" % int % "|P=" % int) currentLength paddingLength
      paddingBytes <- liftIO $ rollBytes paddingLength
      put $ ShakeLengthPadding auth' padding''
      return (chunkLengthBytes <> ciphertext <> paddingBytes, session')
