module Common.Crypto.Aead.Authenticator (Authenticator (..), overhead, seal, open, sizeBytes, encodeSize, decodeSize) where

import Common.Codec.Chunk (ChunkSizeCodec (..))
import Common.Crypto (Ciphertext, Plaintext)
import Common.Crypto.Aead (CipherMethod, decrypt, encrypt, getCipherKind, tagSize)
import Common.Crypto.Aead.NonceGenerator (NonceGenerator, generate)
import Common.Util (decodeWord16BE, encodeWord16BE)
import Control.Monad.Catch (MonadThrow)
import Control.Monad.Trans.State.Strict (StateT, get, gets, put, runState)
import qualified Data.ByteString as B
import GHC.Stack (HasCallStack)

data Authenticator ng = Authenticator CipherMethod ng deriving (Show)

overhead :: Authenticator ng -> Int
overhead (Authenticator method _) = tagSize $ getCipherKind method

seal :: (NonceGenerator ng, MonadThrow m, HasCallStack) => Plaintext -> StateT (Authenticator ng) m Ciphertext
seal plaintext = do
  Authenticator method gen <- get
  let (nonce, gen') = runState generate gen
  ciphertext <- encrypt method nonce B.empty plaintext
  put $ Authenticator method gen'
  return ciphertext

open :: (NonceGenerator ng, MonadThrow m, HasCallStack) => Ciphertext -> StateT (Authenticator ng) m Plaintext
open ciphertext = do
  Authenticator method gen <- get
  let (nonce, gen') = runState generate gen
  plaintext <- decrypt method nonce B.empty ciphertext
  put $ Authenticator method gen'
  return plaintext

instance (NonceGenerator ng) => ChunkSizeCodec (Authenticator ng) where
  sizeBytes = (+ 2) . overhead
  encodeSize = seal . encodeWord16BE
  decodeSize msg = do
    decrypted <- open msg
    let length' = decodeWord16BE decrypted
    gets ((+ length') . overhead)
