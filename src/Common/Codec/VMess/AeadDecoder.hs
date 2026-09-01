{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Common.Codec.VMess.AeadDecoder (AeadDecoder (..), DecodeState (..), DecodeResult, decode) where

import Common.Codec (LeftoverByteString, PendingByteString)
import Common.Codec.Chunk (EmptyPaddingLengthGenerator (EmptyPaddingLengthGenerator), PaddingLengthGenerator, nextPaddingLength)
import qualified Common.Codec.Chunk as Chunk
import Common.Codec.VMess.Aead (Authenticator, ChunkNonce, LengthNonce, decodeSize, open, sizeBytes)
import Common.Codec.VMess.Session (Session)
import Common.Codec.VMess.ShakeSizeParser (ShakeSizeParser)
import Common.Logger (loggers, trace_)
import Control.Exception (SomeException)
import Control.Monad.IO.Class (MonadIO (liftIO))
import Control.Monad.Trans.State.Strict (StateT, get, put, runState, runStateT)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Formatting (format, int, (%))

$(loggers "c.c.v.AeadDecoder" ['trace_])

type DecodeResult = Either SomeException (Maybe (LeftoverByteString, PendingByteString, Session))

data AeadDecoder
  = Default Authenticator
  | AuthLength !Authenticator !Authenticator !DecodeState
  | AuthLengthPadding !Authenticator !Authenticator !ShakeSizeParser !DecodeState
  | ShakeLength !Authenticator !ShakeSizeParser !DecodeState
  | ShakeLengthPadding !Authenticator !ShakeSizeParser !DecodeState
  deriving (Show)

data DecodeState = Padding | Length !Int | Chunk !Int !Int deriving (Show)

decode :: (MonadIO m) => StrictByteString -> Session -> LengthNonce -> ChunkNonce -> StateT AeadDecoder m DecodeResult
decode ciphertext = go ciphertext []
  where
    go :: (MonadIO m) => StrictByteString -> [StrictByteString] -> Session -> LengthNonce -> ChunkNonce -> StateT AeadDecoder m DecodeResult
    go leftover decodedChunks session' lengthNonce' chunkNonce' = do
      result <- decodeChunk leftover session' lengthNonce' chunkNonce'
      case result of
        Left err -> return $ Left err
        Right Nothing -> case decodedChunks of
          [] -> return $ Right Nothing
          [decoded] -> return $ Right $ Just (leftover, decoded, session')
          _ -> return $ Right $ Just (leftover, B.concat $ reverse decodedChunks, session')
        Right (Just (leftover', decoded, session''))
          | B.null decoded -> go leftover' decodedChunks session'' lengthNonce' chunkNonce'
          | otherwise -> go leftover' (decoded : decodedChunks) session'' lengthNonce' chunkNonce'

decodeChunk :: (MonadIO m) => StrictByteString -> Session -> LengthNonce -> ChunkNonce -> StateT AeadDecoder m DecodeResult
decodeChunk ciphertext session lengthNonce chunkNonce = do
  get >>= \case
    Default auth -> do
      let ((plaintext, session'), auth') = runState (open ciphertext session chunkNonce) auth
      put $ Default auth'
      return $ Right $ Just (B.empty, plaintext, session')
    AuthLength auth chunk state -> do
      (decodeResult, (auth', chunk', _, state')) <- liftIO $ runStateT (authLengthDecode ciphertext session lengthNonce chunkNonce) (auth, chunk, EmptyPaddingLengthGenerator, state)
      put $ AuthLength auth' chunk' state'
      return decodeResult
    AuthLengthPadding auth chunk padding state -> do
      (decodeResult, (auth', chunk', padding', state')) <- liftIO $ runStateT (authLengthDecode ciphertext session lengthNonce chunkNonce) (auth, chunk, padding, state)
      put $ AuthLengthPadding auth' chunk' padding' state'
      return decodeResult
    ShakeLength auth chunk state -> do
      case state of
        Padding -> do
          put $ ShakeLength auth chunk $ Length 0
          decodeChunk ciphertext session lengthNonce chunkNonce
        Length _
          | B.length ciphertext < Chunk.sizeBytes chunk -> return $ Right Nothing
          | otherwise -> do
              let (chunkLengthBytes, leftover') = B.splitAt (Chunk.sizeBytes chunk) ciphertext
                  (chunkLength, chunk') = runState (Chunk.decodeSize chunkLengthBytes) chunk
              liftIO $ _trace_ $ format ("decode: C=" % int) chunkLength
              put $ ShakeLength auth chunk' $ Chunk 0 chunkLength
              decodeChunk leftover' session lengthNonce chunkNonce
        Chunk _ chunkLength
          | B.length ciphertext < chunkLength -> return $ Right Nothing
          | otherwise -> do
              let (ciphertext', leftover) = B.splitAt chunkLength ciphertext
                  ((plaintext, session'), auth') = runState (open ciphertext' session chunkNonce) auth
              put $ ShakeLength auth' chunk $ Length 0
              return $ Right $ Just (leftover, plaintext, session')
    ShakeLengthPadding auth shake state -> do
      case state of
        Padding -> do
          let (paddingLength, padding') = runState nextPaddingLength shake
          put $ ShakeLengthPadding auth padding' $ Length paddingLength
          decodeChunk ciphertext session lengthNonce chunkNonce
        Length paddingLength
          | B.length ciphertext < Chunk.sizeBytes shake -> return $ Right Nothing
          | otherwise -> do
              let (chunkLengthBytes, leftover') = B.splitAt (Chunk.sizeBytes shake) ciphertext
                  (chunkLength, shake') = runState (Chunk.decodeSize chunkLengthBytes) shake
              liftIO $ _trace_ $ format ("decode: C=" % int % "|P=" % int) chunkLength paddingLength
              put $ ShakeLengthPadding auth shake' $ Chunk paddingLength chunkLength
              decodeChunk leftover' session lengthNonce chunkNonce
        Chunk paddingLength chunkLength
          | B.length ciphertext < chunkLength -> return $ Right Nothing
          | otherwise -> do
              let (ciphertext', leftover) = B.splitAt (chunkLength - paddingLength) ciphertext
                  ((plaintext, session'), auth') = runState (open ciphertext' session chunkNonce) auth
                  leftover' = B.drop paddingLength leftover
              put $ ShakeLengthPadding auth' shake Padding
              return $ Right $ Just (leftover', plaintext, session')

authLengthDecode :: (PaddingLengthGenerator padding, MonadIO m) => StrictByteString -> Session -> LengthNonce -> ChunkNonce -> StateT (Authenticator, Authenticator, padding, DecodeState) m DecodeResult
authLengthDecode ciphertext session lengthNonce chunkNonce = do
  (auth, chunk, padding, state) <- get
  case state of
    Padding -> do
      let (paddingLength, padding') = runState nextPaddingLength padding
      put (auth, chunk, padding', Length paddingLength)
      authLengthDecode ciphertext session lengthNonce chunkNonce
    Length paddingLength
      | B.length ciphertext < sizeBytes chunk -> return $ Right Nothing
      | otherwise -> do
          let (chunkLengthBytes, leftover') = B.splitAt (sizeBytes chunk) ciphertext
              ((chunkLength, session'), chunk') = runState (decodeSize chunkLengthBytes session lengthNonce) chunk
          liftIO $ _trace_ $ format ("decode: C=" % int % "|P=" % int) chunkLength paddingLength
          put (auth, chunk', padding, Chunk paddingLength chunkLength)
          authLengthDecode leftover' session' lengthNonce chunkNonce
    Chunk paddingLength chunkLength
      | B.length ciphertext < chunkLength -> return $ Right Nothing
      | otherwise -> do
          let (ciphertext', leftover) = B.splitAt (chunkLength - paddingLength) ciphertext
              ((plaintext, session'), auth') = runState (open ciphertext' session chunkNonce) auth
              leftover' = B.drop paddingLength leftover
          put (auth', chunk, padding, Padding)
          return $ Right $ Just (leftover', plaintext, session')
