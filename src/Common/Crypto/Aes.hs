module Common.Crypto.Aes (aes128EcbNoPaddingEncrypt, aes256EcbNoPaddingEncrypt, aes128EcbNoPaddingDecrypt, aes256EcbNoPaddingDecrypt) where

import Common.Crypto (Key)
import Crypto.Cipher.AES (AES128, AES256)
import Crypto.Cipher.Types (BlockCipher (ecbEncrypt), cipherInit, ecbDecrypt)
import Crypto.Error (CryptoFailable, throwCryptoError)
import Data.ByteArray (ByteArray, convert)
import qualified Data.ByteString as B

aes128EcbNoPaddingEncrypt :: (ByteArray b, ByteArray a) => Key -> a -> b
aes128EcbNoPaddingEncrypt key plaintext = do
  let cipher = throwCryptoError (cipherInit (B.take 16 key) :: CryptoFailable AES128)
  convert $ ecbEncrypt cipher plaintext

aes256EcbNoPaddingEncrypt :: (ByteArray b, ByteArray a, ByteArray p) => p -> a -> b
aes256EcbNoPaddingEncrypt key plaintext = do
  let cipher = throwCryptoError (cipherInit key :: CryptoFailable AES256)
  convert $ ecbEncrypt cipher plaintext

aes128EcbNoPaddingDecrypt :: (ByteArray b, ByteArray a) => Key -> a -> b
aes128EcbNoPaddingDecrypt key plaintext = do
  let cipher = throwCryptoError (cipherInit (B.take 16 key) :: CryptoFailable AES128)
  convert $ ecbDecrypt cipher plaintext

aes256EcbNoPaddingDecrypt :: (ByteArray b, ByteArray a, ByteArray p) => p -> a -> b
aes256EcbNoPaddingDecrypt key plaintext = do
  let cipher = throwCryptoError (cipherInit key :: CryptoFailable AES256)
  convert $ ecbDecrypt cipher plaintext
