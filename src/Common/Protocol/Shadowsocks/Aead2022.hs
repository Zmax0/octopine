{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.Shadowsocks.Aead2022 (isAead2022, supportEih, passwordToKeys, decodeKey, sessionSubKey, identitySubKey, sessionCipherKey, identityCipherKey) where

import qualified BLAKE3
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (..))
import Common.Exception (AppExceptionKind (ConfigError), throwApp)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Control.Monad (unless)
import Control.Monad.Catch (MonadThrow)
import qualified Data.ByteArray.Sized as Sized
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import GHC.Stack (HasCallStack)

isAead2022 :: CipherKind -> Bool
isAead2022 Aead2022Blake3Aes128Gcm = True
isAead2022 Aead2022Blake3Aes256Gcm = True
isAead2022 Aead2022Blake3ChaCha8Poly1305 = True
isAead2022 Aead2022Blake3ChaCha20Poly1305 = True
isAead2022 _ = False

supportEih :: CipherKind -> Bool
supportEih Aead2022Blake3Aes128Gcm = True
supportEih Aead2022Blake3Aes256Gcm = True
supportEih _ = False

passwordToKeys :: (MonadThrow t, HasCallStack) => CipherKind -> T.Text -> t (Key, [Key])
passwordToKeys kind = go 1 []
  where
    go index identityKeys password = do
      let (part, rest) = T.breakOn ":" password
      key <- decodeKey kind ("shadowsocks key " ++ show (index :: Int)) part
      if T.null rest then return (key, reverse identityKeys) else go (index + 1) (key : identityKeys) (T.drop 1 rest)

decodeKey :: (MonadThrow m, HasCallStack) => CipherKind -> String -> T.Text -> m Key
decodeKey kind field part = do
  key <- either (const $ throwApp ConfigError $ field ++ " is not valid Base64") return $ B64.decode $ TE.encodeUtf8 part
  unless (B.length key == keySize kind) $ throwApp ConfigError $ field ++ ": invalid length, expected=" ++ show (keySize kind) ++ ", actual=" ++ show (B.length key)
  pure key

sessionCipherKey :: CipherKind -> Key -> Salt -> Key
sessionCipherKey kind key salt = B.take (keySize kind) $ sessionSubKey key salt

identityCipherKey :: CipherKind -> Key -> Salt -> Key
identityCipherKey kind key salt = B.take (keySize kind) $ identitySubKey key salt

sessionSubKey :: Key -> Salt -> Key
sessionSubKey key (Salt salt) = do
  let context = "shadowsocks 2022 session subkey" :: StrictByteString
      digest = BLAKE3.derive context [key <> salt] :: BLAKE3.Digest BLAKE3.DEFAULT_DIGEST_LEN
  Sized.unSizedByteArray (Sized.convert digest :: Sized.SizedByteArray BLAKE3.DEFAULT_DIGEST_LEN StrictByteString)

identitySubKey :: Key -> Salt -> Key
identitySubKey key (Salt salt) = do
  let context = "shadowsocks 2022 identity subkey" :: StrictByteString
      digest = BLAKE3.derive context [key <> salt] :: BLAKE3.Digest BLAKE3.DEFAULT_DIGEST_LEN
  Sized.unSizedByteArray (Sized.convert digest :: Sized.SizedByteArray BLAKE3.DEFAULT_DIGEST_LEN StrictByteString)
