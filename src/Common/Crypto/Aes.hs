module Common.Crypto.Aes (aes128EcbNoPaddingEncrypt, aes256EcbNoPaddingEncrypt, aes128EcbNoPaddingDecrypt, aes256EcbNoPaddingDecrypt) where

import Common.Crypto (Key)
import Common.Exception (AppExceptionKind (InvariantError), throwApp)
import Control.Monad.Catch (MonadThrow)
import Crypto.Cipher.AES (AES128, AES256)
import Crypto.Cipher.Types (BlockCipher (ecbEncrypt), cipherInit, ecbDecrypt)
import Crypto.Error (CryptoFailable, onCryptoFailure)
import Data.ByteArray (ByteArray, convert)
import GHC.Stack (HasCallStack)

aes128EcbNoPaddingEncrypt :: (MonadThrow m, HasCallStack, ByteArray b, ByteArray a) => Key -> a -> m b
aes128EcbNoPaddingEncrypt key plaintext = do
  cipher <- cryptoOrThrow InvariantError "initialize AES128 ECB" (cipherInit key :: CryptoFailable AES128)
  pure $ convert $ ecbEncrypt cipher plaintext

aes256EcbNoPaddingEncrypt :: (MonadThrow m, HasCallStack, ByteArray b, ByteArray a, ByteArray p) => p -> a -> m b
aes256EcbNoPaddingEncrypt key plaintext = do
  cipher <- cryptoOrThrow InvariantError "initialize AES256 ECB" (cipherInit key :: CryptoFailable AES256)
  pure $ convert $ ecbEncrypt cipher plaintext

aes128EcbNoPaddingDecrypt :: (MonadThrow m, HasCallStack, ByteArray b, ByteArray a) => Key -> a -> m b
aes128EcbNoPaddingDecrypt key plaintext = do
  cipher <- cryptoOrThrow InvariantError "initialize AES128 ECB" (cipherInit key :: CryptoFailable AES128)
  pure $ convert $ ecbDecrypt cipher plaintext

aes256EcbNoPaddingDecrypt :: (MonadThrow m, HasCallStack, ByteArray b, ByteArray a, ByteArray p) => p -> a -> m b
aes256EcbNoPaddingDecrypt key plaintext = do
  cipher <- cryptoOrThrow InvariantError "initialize AES256 ECB" (cipherInit key :: CryptoFailable AES256)
  pure $ convert $ ecbDecrypt cipher plaintext

cryptoOrThrow :: (MonadThrow m, HasCallStack) => AppExceptionKind -> String -> CryptoFailable a -> m a
cryptoOrThrow kind operation = onCryptoFailure (\err -> throwApp kind (operation ++ ": " ++ show err)) pure
