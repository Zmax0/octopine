{-# LANGUAGE OverloadedStrings #-}

module Common.Crypto.AeadTest (spec) where

import Common.Crypto (Ciphertext, Key)
import Common.Crypto.Aead (CipherKind (ChaCha8Poly1305, keySize, nonceSize), CipherMethod, decrypt, encrypt, getCipherKind, newCipherMethod)
import Common.Util (showBase64)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import Test.Hspec (Expectation, Spec, describe, it, shouldBe)

_key :: Key
_key = B64.decodeLenient "1nFNRRLWhYe4Tq2yBimnQTNMr0RIDhgwqZMRCWSoFcc="

_plaintext :: StrictByteString
_plaintext = "plaintext"

_ciphertext :: StrictByteString
_ciphertext = "ciphertext"

spec :: Spec
spec =
  describe "Common.Crypto.Aead" $ do
    it "testChaCha8Poly1305" $ do
      let method = _newCipherMethod ChaCha8Poly1305
      testEncrypt method "DvAxs1hCeM+VySozlDhrdGewiF/WHljuRA=="
      testDecrypt method "HfUgslNEadKZLZkH8tfHEif6qmmM54Pv6l4"

_newCipherMethod :: CipherKind -> CipherMethod
_newCipherMethod kind = newCipherMethod kind $ copyOf (keySize kind) _key

testEncrypt :: CipherMethod -> String -> Expectation
testEncrypt method expect = do
  let size = nonceSize . getCipherKind $ method
      nonce = B.replicate size 0
      encrypt' = showBase64 . encrypt method nonce B.empty
  encrypt' _plaintext `shouldBe` expect

testDecrypt :: CipherMethod -> Ciphertext -> Expectation
testDecrypt method ciphertext = do
  let size = nonceSize . getCipherKind $ method
      nonce = B.replicate size 0
      decrypt' = decrypt method nonce B.empty
  decrypt' (B64.decodeLenient ciphertext) `shouldBe` _ciphertext

copyOf :: Int -> StrictByteString -> StrictByteString
copyOf n bs
  | B.length bs >= n = B.take n bs
  | otherwise = bs <> B.replicate (n - B.length bs) 0
