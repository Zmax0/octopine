{-# LANGUAGE RankNTypes #-}

module Common.Codec.VMess.Aead (Authenticator (..), LengthNonce, ChunkNonce, seal, open, sizeBytes, encodeSize, decodeSize, generateChacha20Poly1305Key) where

import Common.Codec.VMess.Session (Session)
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherMethod, decrypt, encrypt, getCipherKind, tagSize)
import Common.Crypto.Aead.NonceGenerator (CountingNonceGenerator, generateT)
import Common.Util (decodeWord16BE, encodeWord16BE)
import Control.Lens (Lens', (&), (.~), (^.))
import Control.Monad.Trans.State.Strict (State, get, put, runState)
import Crypto.Hash (Digest, hash)
import Crypto.Hash.Algorithms (MD5)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B

data Authenticator = Authenticator CipherMethod CountingNonceGenerator deriving (Show)

type LengthNonce = Lens' Session StrictByteString

type ChunkNonce = Lens' Session StrictByteString

seal :: StrictByteString -> Session -> Lens' Session StrictByteString -> State Authenticator (StrictByteString, Session)
seal plaintext session function = do
  Authenticator method gen <- get
  let nonce = session ^. function
      ((nonce', generatedNonce), gen') = runState (generateT nonce) gen
      ciphertext = encrypt method generatedNonce B.empty plaintext
      session' = session & function .~ nonce'
  put $ Authenticator method gen'
  return (ciphertext, session')

open :: StrictByteString -> Session -> Lens' Session StrictByteString -> State Authenticator (StrictByteString, Session)
open ciphertext session function = do
  Authenticator method gen <- get
  let nonce = session ^. function
      ((nonce', generatedNonce), gen') = runState (generateT nonce) gen
      plaintext = decrypt method generatedNonce B.empty ciphertext
      session' = session & function .~ nonce'
  put $ Authenticator method gen'
  return (plaintext, session')

sizeBytes :: Authenticator -> Int
sizeBytes = (+ 2) . overhead

encodeSize :: Int -> Session -> Lens' Session StrictByteString -> State Authenticator (StrictByteString, Session)
encodeSize length' session function = do
  seal (encodeWord16BE length') session function

decodeSize :: StrictByteString -> Session -> Lens' Session StrictByteString -> State Authenticator (Int, Session)
decodeSize msg session function = do
  (decrypted, session') <- open msg session function
  auth <- get
  let length' = decodeWord16BE decrypted
  return (length' + overhead auth, session')

overhead :: Authenticator -> Int
overhead (Authenticator method _) = tagSize $ getCipherKind method

generateChacha20Poly1305Key :: Key -> Key
generateChacha20Poly1305Key bytes = do
  let temp' = BA.convert (hash bytes :: Digest MD5)
      left = B.take 16 temp'
      temp'' = BA.convert (hash left :: Digest MD5)
      right = B.take 16 temp''
  left <> right
