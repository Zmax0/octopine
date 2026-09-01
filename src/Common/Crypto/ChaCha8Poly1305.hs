module Common.Crypto.ChaCha8Poly1305 (State (State), appendAAD, finalizeAAD, encrypt, decrypt, finalize) where

import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.MAC.Poly1305 as Poly1305
import Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.ByteString.Builder (toLazyByteString, word64LE)
import GHC.Word (Word64)

data State = State ChaCha.State Poly1305.State Word64 Word64

appendAAD :: (ByteArrayAccess bytes) => bytes -> State -> State
appendAAD bytes (State encryptionState macState aadLength ciphertextLength) =
  State encryptionState (Poly1305.update macState bytes) (aadLength + fromIntegral (BA.length bytes)) ciphertextLength

finalizeAAD :: State -> State
finalizeAAD (State encryptionState macState aadLength ciphertextLength) =
  State encryptionState (Poly1305.update macState $ pad16 aadLength) aadLength ciphertextLength

encrypt :: (ByteArray bytes) => State -> bytes -> (bytes, State)
encrypt (State encryptionState macState aadLength ciphertextLength) plaintext =
  let (ciphertext, encryptionState') = ChaCha.combine encryptionState plaintext
   in (ciphertext, State encryptionState' (Poly1305.update macState ciphertext) aadLength (ciphertextLength + fromIntegral (BA.length ciphertext)))

decrypt :: (ByteArray bytes) => State -> bytes -> (bytes, State)
decrypt (State encryptionState macState aadLength ciphertextLength) ciphertext =
  let (plaintext, encryptionState') = ChaCha.combine encryptionState ciphertext
   in (plaintext, State encryptionState' (Poly1305.update macState ciphertext) aadLength (ciphertextLength + fromIntegral (BA.length ciphertext)))

finalize :: State -> Poly1305.Auth
finalize (State _ macState aadLength ciphertextLength) =
  Poly1305.finalize $ Poly1305.updates macState [pad16 ciphertextLength, lengthBytes]
  where
    lengthBytes = B.toStrict $ toLazyByteString $ word64LE aadLength <> word64LE ciphertextLength

pad16 :: Word64 -> B.ByteString
pad16 length'
  | remainder == 0 = B.empty
  | otherwise = B.replicate (16 - remainder) 0
  where
    remainder = fromIntegral $ length' `mod` 16
